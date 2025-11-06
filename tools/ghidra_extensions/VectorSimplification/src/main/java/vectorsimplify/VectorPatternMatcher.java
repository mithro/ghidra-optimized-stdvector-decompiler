package vectorsimplify;

import ghidra.program.model.pcode.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import java.util.*;

/**
 * Identifies std::vector usage patterns in pcode operations.
 *
 * Recognizes patterns like:
 * - (mylast - myfirst) >> N  ->  vector::size()
 * - *myfirst                 ->  vector::data()
 * - mylast == myfirst        ->  vector::empty()
 */
public class VectorPatternMatcher {

	// Vector member offsets in MSVC std::_Vector_val (64-bit)
	// Structure: vector->_Mypair(0x0)->_Myval2(0x0)->_Myfirst/Last/End
	// Absolute offsets from vector pointer:
	private static final long OFFSET_MYFIRST = 0x0;  // First element pointer
	private static final long OFFSET_MYLAST = 0x8;   // Last element pointer (one past end)
	private static final long OFFSET_MYEND = 0x10;   // End of capacity pointer

	/**
	 * Simple test method to verify the class is being loaded correctly.
	 */
	public void testMethod() {
		try {
			java.io.FileWriter fw = new java.io.FileWriter("/tmp/patternmatcher_test.txt", true);
			fw.write("testMethod() was called at " + System.currentTimeMillis() + "\n");
			fw.close();
		} catch (Exception e) {
			System.err.println("ERROR in testMethod: " + e.getMessage());
			e.printStackTrace();
		}
	}

	/**
	 * Find all vector patterns in a high function.
	 */
	public List<VectorPattern> findVectorPatterns(HighFunction highFunc) {
		System.err.println("=== findVectorPatterns ENTERED ===");
		System.err.flush();

		// Write to file to prove this method is called
		try {
			java.io.FileWriter fw = new java.io.FileWriter("/tmp/vector_matcher_called.txt", true);
			fw.write("findVectorPatterns CALLED at " + System.currentTimeMillis() + "\n");
			fw.close();
		} catch (Exception e) {
			System.err.println("ERROR writing to log file: " + e.getMessage());
			e.printStackTrace();
		}

		List<VectorPattern> patterns = new ArrayList<>();

		// Iterate through all pcode ops
		Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
		int opCount = 0;
		int equalCount = 0;
		while (ops.hasNext()) {
			PcodeOpAST op = ops.next();
			opCount++;

			if (op.getOpcode() == PcodeOp.INT_EQUAL) {
				equalCount++;
			}

			// Check for size pattern
			VectorPattern sizePattern = matchSizePattern(op);
			if (sizePattern != null) {
				patterns.add(sizePattern);
				continue;
			}

			// Check for empty pattern
			VectorPattern emptyPattern = matchEmptyPattern(op);
			if (emptyPattern != null) {
				patterns.add(emptyPattern);
				continue;
			}

			// TODO: DATA pattern temporarily disabled for debugging
			// Need to verify SIZE/EMPTY work correctly first
			// VectorPattern dataPattern = matchDataPattern(op);
			// if (dataPattern != null) {
			//     patterns.add(dataPattern);
			// }
		}

		// Write results to file
		try {
			java.io.FileWriter fw = new java.io.FileWriter("/tmp/vector_matcher_called.txt", true);
			fw.write("Processed " + opCount + " ops, " + equalCount + " INT_EQUAL, found " + patterns.size() + " patterns\n");
			fw.close();
		} catch (Exception e) {
			System.err.println("ERROR writing results to log file: " + e.getMessage());
			e.printStackTrace();
		}

		return patterns;
	}

	/**
	 * Match pattern: (mylast - myfirst) >> shift
	 * Represents: vector.size()
	 */
	private VectorPattern matchSizePattern(PcodeOpAST op) {
		// Look for INT_RIGHT (right shift)
		if (op.getOpcode() != PcodeOp.INT_RIGHT) {
			return null;
		}

		if (op.getNumInputs() < 2) {
			return null;
		}

		// Get the subtraction operation
		Varnode subVarnode = op.getInput(0);
		if (subVarnode == null) {
			return null;
		}

		PcodeOp subOp = subVarnode.getDef();
		if (subOp == null || subOp.getOpcode() != PcodeOp.INT_SUB) {
			return null;
		}

		if (subOp.getNumInputs() < 2) {
			return null;
		}

		// Check if operands are vector members
		Varnode mylastVarnode = subOp.getInput(0);
		Varnode myfirstVarnode = subOp.getInput(1);

		VectorMember mylast = identifyVectorMember(mylastVarnode);
		VectorMember myfirst = identifyVectorMember(myfirstVarnode);

		if (mylast != null && mylast.type == VectorMemberType.MYLAST &&
			myfirst != null && myfirst.type == VectorMemberType.MYFIRST) {

			// Verify they're from the same vector
			if (isSameVectorBase(mylast.baseVarnode, myfirst.baseVarnode)) {
				// Get shift amount (element size)
				Varnode shiftVarnode = op.getInput(1);
				long shiftAmount = shiftVarnode.getOffset();

				return new VectorPattern(VectorPatternType.SIZE, op, mylast.baseVarnode,
					shiftAmount);
			}
		}

		return null;
	}

	/**
	 * Match pattern: myfirst == mylast
	 * Represents: vector.empty()
	 */
	private VectorPattern matchEmptyPattern(PcodeOpAST op) {
		// Look for INT_EQUAL
		if (op.getOpcode() != PcodeOp.INT_EQUAL) {
			return null;
		}

		if (op.getNumInputs() < 2) {
			return null;
		}

		Varnode operand1 = op.getInput(0);
		Varnode operand2 = op.getInput(1);

		VectorMember member1 = identifyVectorMember(operand1);
		VectorMember member2 = identifyVectorMember(operand2);

		if (member1 != null && member2 != null) {
			// Check if comparing first and last
			boolean isEmptyCheck = (member1.type == VectorMemberType.MYFIRST &&
				member2.type == VectorMemberType.MYLAST) ||
				(member1.type == VectorMemberType.MYLAST &&
					member2.type == VectorMemberType.MYFIRST);

			if (isEmptyCheck && isSameVectorBase(member1.baseVarnode, member2.baseVarnode)) {
				return new VectorPattern(VectorPatternType.EMPTY, op, member1.baseVarnode, 0);
			}
		}

		return null;
	}

	/**
	 * Match pattern: *myfirst or &myfirst
	 * Represents: vector.data()
	 */
	private VectorPattern matchDataPattern(PcodeOpAST op) {
		// Look for LOAD or PTRSUB accessing myfirst
		if (op.getOpcode() != PcodeOp.LOAD && op.getOpcode() != PcodeOp.PTRSUB) {
			return null;
		}

		// Check if we're accessing a vector member
		for (int i = 0; i < op.getNumInputs(); i++) {
			Varnode input = op.getInput(i);
			VectorMember member = identifyVectorMember(input);

			if (member != null && member.type == VectorMemberType.MYFIRST) {
				return new VectorPattern(VectorPatternType.DATA, op, member.baseVarnode, 0);
			}
		}

		return null;
	}

	/**
	 * Identify if a varnode represents a vector member access.
	 */
	private VectorMember identifyVectorMember(Varnode varnode) {
		System.err.println("identifyVectorMember called");
		if (varnode == null) {
			System.err.println("  varnode is null");
			return null;
		}

		PcodeOp defOp = varnode.getDef();
		System.err.println("  defOp: " + (defOp != null ? defOp.getMnemonic() : "null"));
		if (defOp == null) {
			return null;
		}

		// Check for PTRSUB or PTRADD with vector member offset
		if (defOp.getOpcode() == PcodeOp.PTRSUB || defOp.getOpcode() == PcodeOp.PTRADD) {
			if (defOp.getNumInputs() >= 2) {
				Varnode baseVarnode = defOp.getInput(0);
				Varnode offsetVarnode = defOp.getInput(1);

				if (offsetVarnode.isConstant()) {
					long offset = offsetVarnode.getOffset();

					VectorMemberType memberType = null;
					if (offset == OFFSET_MYFIRST) {
						memberType = VectorMemberType.MYFIRST;
					}
					else if (offset == OFFSET_MYLAST) {
						memberType = VectorMemberType.MYLAST;
					}
					else if (offset == OFFSET_MYEND) {
						memberType = VectorMemberType.MYEND;
					}

					// FIX: Trace back to source variable to find vector type
					// The baseVarnode might be an intermediate result (pointer, etc.)
					// We need to find the original variable that has the vector type
					if (memberType != null) {
						Varnode sourceVar = traceToSourceVariable(baseVarnode);
						if (sourceVar != null && isVectorType(sourceVar)) {
							return new VectorMember(memberType, baseVarnode);
						}
					}
				}
			}
		}

		// Check for LOAD operations accessing vector members
		// Pattern: varnode = LOAD(address) where address = base + offset
		// This handles cases where compiler loads members into local variables first
		if (defOp.getOpcode() == PcodeOp.LOAD) {
			if (defOp.getNumInputs() >= 2) {
				// Input 0 is space, input 1 is address
				Varnode addrVarnode = defOp.getInput(1);

				// Check if address is computed as base + offset
				PcodeOp addrDef = addrVarnode.getDef();
				if (addrDef != null &&
				    (addrDef.getOpcode() == PcodeOp.PTRSUB || addrDef.getOpcode() == PcodeOp.PTRADD)) {

					if (addrDef.getNumInputs() >= 2) {
						Varnode baseVarnode = addrDef.getInput(0);
						Varnode offsetVarnode = addrDef.getInput(1);

						if (offsetVarnode.isConstant()) {
							long offset = offsetVarnode.getOffset();

							VectorMemberType memberType = null;
							if (offset == OFFSET_MYFIRST) {
								memberType = VectorMemberType.MYFIRST;
							}
							else if (offset == OFFSET_MYLAST) {
								memberType = VectorMemberType.MYLAST;
							}
							else if (offset == OFFSET_MYEND) {
								memberType = VectorMemberType.MYEND;
							}

							if (memberType != null) {
								// Check if baseVarnode has vector type
								System.err.println("LOAD: memberType=" + memberType + " offset=0x" + Long.toHexString(offset));
								System.err.println("LOAD: base=" + baseVarnode);
								boolean isVec = isVectorType(baseVarnode);
								System.err.println("LOAD: isVector=" + isVec);
								if (isVec) {
									System.err.println(">>> FOUND VECTOR MEMBER VIA LOAD! <<<");
									return new VectorMember(memberType, baseVarnode);
								}
							}
						}
					}
				}
			}
		}

		return null;
	}

	/**
	 * Trace a varnode back to its source variable.
	 *
	 * Follows through COPY, CAST, PTRSUB, PTRADD, and LOAD operations to find
	 * the original variable (parameter, local, etc.) that has type information.
	 *
	 * @param varnode The varnode to trace
	 * @return The source variable, or the original varnode if can't trace further
	 */
	private Varnode traceToSourceVariable(Varnode varnode) {
		if (varnode == null) {
			return null;
		}

		// Limit depth to prevent infinite loops
		int maxDepth = 20;
		Varnode current = varnode;

		for (int depth = 0; depth < maxDepth; depth++) {
			// If this varnode has vector type info, we found it!
			if (hasVectorTypeInfo(current)) {
				return current;
			}

			// If it's a free varnode (parameter, local variable), stop here
			if (current.isFree() || current.isInput()) {
				return current;
			}

			PcodeOp defOp = current.getDef();
			if (defOp == null) {
				// No definition - this is as far as we can trace
				return current;
			}

			int opcode = defOp.getOpcode();

			// Trace through operations that just transform the value
			if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
				// These just copy/cast the value - trace to input
				if (defOp.getNumInputs() > 0) {
					current = defOp.getInput(0);
					continue;
				}
			}
			else if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.PTRADD) {
				// Pointer arithmetic - trace to base pointer
				if (defOp.getNumInputs() > 0) {
					current = defOp.getInput(0);
					continue;
				}
			}
			else if (opcode == PcodeOp.LOAD) {
				// Load from memory - trace to address
				if (defOp.getNumInputs() > 1) {
					current = defOp.getInput(1);
					continue;
				}
			}

			// Can't trace further
			return current;
		}

		return current;
	}

	/**
	 * Quick check if a varnode has vector type information.
	 * Used during tracing to find the best candidate.
	 */
	private boolean hasVectorTypeInfo(Varnode varnode) {
		if (varnode == null) {
			return false;
		}

		HighVariable highVar = varnode.getHigh();
		if (highVar == null) {
			return false;
		}

		DataType dataType = highVar.getDataType();
		if (dataType == null) {
			return false;
		}

		String typeName = dataType.getName();
		if (typeName != null && (typeName.contains("vector<") ||
		                         typeName.contains("Vector_val"))) {
			return true;
		}

		// Check for pointer to vector
		if (dataType instanceof Pointer) {
			Pointer ptrType = (Pointer) dataType;
			DataType pointedType = ptrType.getDataType();
			if (pointedType != null) {
				String pointedName = pointedType.getName();
				if (pointedName != null && (pointedName.contains("vector<") ||
				                             pointedName.contains("Vector_val"))) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check if a varnode has a std::vector type.
	 * Uses Ghidra's type information to validate.
	 */
	private boolean isVectorType(Varnode varnode) {
		if (varnode == null) {
			return false;
		}

		// Try to get the high-level type information
		HighVariable highVar = varnode.getHigh();
		if (highVar == null) {
			// No type info available - REJECT for safety
			// Many non-vector structs use offset 0x8/0x10/0x18
			return false;
		}

		// Get the data type
		DataType dataType = highVar.getDataType();
		if (dataType == null) {
			// No type info available - REJECT
			return false;
		}

		// Get the type name
		String typeName = dataType.getName();
		if (typeName == null) {
			// No type name - REJECT
			return false;
		}

		// Check if this is a vector type
		// Handles: vector<T>, std::vector<T>, _Vector_val<T>
		if (typeName.contains("vector<") || typeName.contains("vector_") ||
			typeName.contains("Vector_val")) {
			return true;
		}

		// Check for pointer/reference to vector
		if (dataType instanceof Pointer) {
			Pointer ptrType = (Pointer) dataType;
			DataType pointedType = ptrType.getDataType();
			if (pointedType != null) {
				String pointedName = pointedType.getName();
				if (pointedName != null && (pointedName.contains("vector<") ||
					pointedName.contains("vector_") || pointedName.contains("Vector_val"))) {
					return true;
				}
			}
		}

		// Check the full path name (includes namespace)
		String pathName = dataType.getPathName();
		if (pathName != null && (pathName.contains("/std/vector") ||
			pathName.contains("/vector<") || pathName.contains("std::vector"))) {
			return true;
		}

		// REJECT: We have type info, but it's not a vector type
		// This filters out false positives where offset 0x8/0x10/0x18 is used
		// for non-vector structs
		return false;
	}

	/**
	 * Check if two varnodes refer to the same vector base.
	 */
	private boolean isSameVectorBase(Varnode base1, Varnode base2) {
		if (base1 == null || base2 == null) {
			return false;
		}

		// Simple check: same varnode
		if (base1.equals(base2)) {
			return true;
		}

		// Trace both back to source variables and check if they're the same
		Varnode source1 = traceToSourceVariable(base1);
		Varnode source2 = traceToSourceVariable(base2);

		if (source1 != null && source2 != null && source1.equals(source2)) {
			return true;
		}

		// Check if they have the same HighVariable (same variable)
		if (base1.getHigh() != null && base2.getHigh() != null) {
			if (base1.getHigh().equals(base2.getHigh())) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Represents a vector member being accessed.
	 */
	private static class VectorMember {
		VectorMemberType type;
		Varnode baseVarnode;

		VectorMember(VectorMemberType type, Varnode baseVarnode) {
			this.type = type;
			this.baseVarnode = baseVarnode;
		}
	}

	/**
	 * Types of vector members.
	 */
	private enum VectorMemberType {
		MYFIRST, MYLAST, MYEND
	}
}
