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

			// Check for capacity pattern
			VectorPattern capacityPattern = matchCapacityPattern(op);
			if (capacityPattern != null) {
				patterns.add(capacityPattern);
				continue;
			}

			// Check for empty pattern
			VectorPattern emptyPattern = matchEmptyPattern(op);
			if (emptyPattern != null) {
				patterns.add(emptyPattern);
				continue;
			}

			// Check for data pattern (only when pointer is actually used)
			VectorPattern dataPattern = matchDataPattern(op);
			if (dataPattern != null) {
				patterns.add(dataPattern);
				continue;
			}
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
		// Look for INT_RIGHT or INT_SRIGHT (signed right shift)
		if (op.getOpcode() != PcodeOp.INT_RIGHT && op.getOpcode() != PcodeOp.INT_SRIGHT) {
			return null;
		}

		if (op.getNumInputs() < 2) {
			return null;
		}

		System.err.println("\nmatchSizePattern checking shift:");
		System.err.println("  shift op: " + op);

		// Get the subtraction operation
		Varnode subVarnode = op.getInput(0);
		if (subVarnode == null) {
			return null;
		}

		System.err.println("  sub varnode: " + subVarnode);

		PcodeOp subOp = subVarnode.getDef();
		System.err.println("  sub def: " + (subOp != null ? subOp.getMnemonic() : "null"));

		if (subOp == null || subOp.getOpcode() != PcodeOp.INT_SUB) {
			return null;
		}

		if (subOp.getNumInputs() < 2) {
			return null;
		}

		// Check if operands are vector members
		Varnode mylastVarnode = subOp.getInput(0);
		Varnode myfirstVarnode = subOp.getInput(1);

		System.err.println("  checking operands:");
		System.err.println("    operand 0: " + mylastVarnode);
		System.err.println("    operand 1: " + myfirstVarnode);

		VectorMember mylast = identifyVectorMember(mylastVarnode);
		VectorMember myfirst = identifyVectorMember(myfirstVarnode);

		System.err.println("  mylast: " + (mylast != null ? mylast.type + " base=" + mylast.baseVarnode : "null"));
		System.err.println("  myfirst: " + (myfirst != null ? myfirst.type + " base=" + myfirst.baseVarnode : "null"));

		if (mylast != null && mylast.type == VectorMemberType.MYLAST &&
			myfirst != null && myfirst.type == VectorMemberType.MYFIRST) {

			// Verify they're from the same vector
			boolean sameBase = isSameVectorBase(mylast.baseVarnode, myfirst.baseVarnode);
			System.err.println("  sameBase: " + sameBase);

			if (sameBase) {
				// Get shift amount (element size)
				Varnode shiftVarnode = op.getInput(1);
				long shiftAmount = shiftVarnode.getOffset();
				System.err.println("  >>> MATCHED SIZE PATTERN! shift=" + shiftAmount);

				return new VectorPattern(VectorPatternType.SIZE, op, mylast.baseVarnode,
					shiftAmount);
			}
		}

		return null;
	}

	/**
	 * Match pattern: (myend - myfirst) >> shift
	 * Represents: vector.capacity()
	 */
	private VectorPattern matchCapacityPattern(PcodeOpAST op) {
		// Look for INT_RIGHT or INT_SRIGHT (signed right shift)
		if (op.getOpcode() != PcodeOp.INT_RIGHT && op.getOpcode() != PcodeOp.INT_SRIGHT) {
			return null;
		}

		if (op.getNumInputs() < 2) {
			return null;
		}

		System.err.println("\nmatchCapacityPattern checking shift:");
		System.err.println("  shift op: " + op);

		// Get the subtraction operation
		Varnode subVarnode = op.getInput(0);
		if (subVarnode == null) {
			return null;
		}

		System.err.println("  sub varnode: " + subVarnode);

		PcodeOp subOp = subVarnode.getDef();
		System.err.println("  sub def: " + (subOp != null ? subOp.getMnemonic() : "null"));

		if (subOp == null || subOp.getOpcode() != PcodeOp.INT_SUB) {
			return null;
		}

		if (subOp.getNumInputs() < 2) {
			return null;
		}

		// Check if operands are vector members
		Varnode myendVarnode = subOp.getInput(0);
		Varnode myfirstVarnode = subOp.getInput(1);

		System.err.println("  checking operands:");
		System.err.println("    operand 0: " + myendVarnode);
		System.err.println("    operand 1: " + myfirstVarnode);

		VectorMember myend = identifyVectorMember(myendVarnode);
		VectorMember myfirst = identifyVectorMember(myfirstVarnode);

		System.err.println("  myend: " + (myend != null ? myend.type + " base=" + myend.baseVarnode : "null"));
		System.err.println("  myfirst: " + (myfirst != null ? myfirst.type + " base=" + myfirst.baseVarnode : "null"));

		if (myend != null && myend.type == VectorMemberType.MYEND &&
			myfirst != null && myfirst.type == VectorMemberType.MYFIRST) {

			// Verify they're from the same vector
			boolean sameBase = isSameVectorBase(myend.baseVarnode, myfirst.baseVarnode);
			System.err.println("  sameBase: " + sameBase);

			if (sameBase) {
				// Get shift amount (element size)
				Varnode shiftVarnode = op.getInput(1);
				long shiftAmount = shiftVarnode.getOffset();
				System.err.println("  >>> MATCHED CAPACITY PATTERN! shift=" + shiftAmount);

				return new VectorPattern(VectorPatternType.CAPACITY, op, myend.baseVarnode,
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

		System.err.println("\nmatchEmptyPattern checking INT_EQUAL:");
		System.err.println("  operand1: " + operand1);
		System.err.println("  operand2: " + operand2);

		VectorMember member1 = identifyVectorMember(operand1);
		VectorMember member2 = identifyVectorMember(operand2);

		System.err.println("  member1: " + (member1 != null ? member1.type + " base=" + member1.baseVarnode : "null"));
		System.err.println("  member2: " + (member2 != null ? member2.type + " base=" + member2.baseVarnode : "null"));

		if (member1 != null && member2 != null) {
			// Check if comparing first and last
			boolean isEmptyCheck = (member1.type == VectorMemberType.MYFIRST &&
				member2.type == VectorMemberType.MYLAST) ||
				(member1.type == VectorMemberType.MYLAST &&
					member2.type == VectorMemberType.MYFIRST);

			System.err.println("  isEmptyCheck: " + isEmptyCheck);

			if (isEmptyCheck) {
				boolean sameBase = isSameVectorBase(member1.baseVarnode, member2.baseVarnode);
				System.err.println("  sameBase: " + sameBase);

				if (sameBase) {
					System.err.println("  >>> MATCHED EMPTY PATTERN! <<<");
					return new VectorPattern(VectorPatternType.EMPTY, op, member1.baseVarnode, 0);
				}
			}
		}

		return null;
	}

	/**
	 * Match pattern: Load from _Myfirst when used as data pointer
	 * Represents: vector.data()
	 *
	 * Only matches when the loaded pointer value is actually dereferenced or
	 * used in pointer arithmetic, not when it's just assigned to a variable.
	 */
	private VectorPattern matchDataPattern(PcodeOpAST op) {
		// Look for LOAD that reads the _Myfirst field value
		if (op.getOpcode() != PcodeOp.LOAD) {
			return null;
		}

		if (op.getNumInputs() < 2) {
			return null;
		}

		System.err.println("\nmatchDataPattern checking LOAD:");
		System.err.println("  op: " + op);

		// The address we're loading from (should be offset to _Myfirst field)
		Varnode addressVarnode = op.getInput(1);
		VectorMember member = identifyVectorMember(addressVarnode);

		System.err.println("  address: " + addressVarnode);
		System.err.println("  member: " + (member != null ? member.type : "null"));

		// Check if we're loading from _Myfirst (offset 0x0)
		if (member != null && member.type == VectorMemberType.MYFIRST) {
			// This loads the pointer value stored in _Myfirst
			// Only match if the result is used as a pointer (dereferenced or in pointer arithmetic)
			Varnode result = op.getOutput();
			System.err.println("  result varnode: " + result);

			if (result != null) {
				boolean isUsedAsPtr = isUsedAsPointer(result);
				System.err.println("  isUsedAsPointer: " + isUsedAsPtr);

				if (isUsedAsPtr) {
					System.err.println("  >>> MATCHED DATA PATTERN! <<<");
					return new VectorPattern(VectorPatternType.DATA, op, member.baseVarnode, 0);
				} else {
					System.err.println("  Not used as pointer - skipping (likely iterator assignment)");
				}
			}
		}

		return null;
	}

	/**
	 * Check if a varnode is used as a pointer (dereferenced or used in pointer arithmetic)
	 * rather than just stored in a variable.
	 * Recursively traces through CAST/COPY operations.
	 */
	private boolean isUsedAsPointer(Varnode varnode) {
		return isUsedAsPointerRecursive(varnode, new java.util.HashSet<Varnode>());
	}

	/**
	 * Recursive helper to check pointer usage, tracking visited nodes to avoid cycles.
	 */
	private boolean isUsedAsPointerRecursive(Varnode varnode, java.util.Set<Varnode> visited) {
		// Prevent infinite recursion on cycles
		if (visited.contains(varnode)) {
			return false;
		}
		visited.add(varnode);

		Iterator<PcodeOp> descendants = varnode.getDescendants();

		while (descendants.hasNext()) {
			PcodeOp use = descendants.next();
			int opcode = use.getOpcode();

			System.err.println("    use: " + use.getMnemonic() + " at " + use.getSeqnum().getTarget());

			// Check if used as address operand in LOAD/STORE
			if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
				// In LOAD/STORE, input 1 is the address
				if (use.getNumInputs() >= 2 && use.getInput(1) == varnode) {
					System.err.println("      -> used as LOAD/STORE address!");
					return true;
				}
			}

			// Check if used in pointer arithmetic
			if (opcode == PcodeOp.PTRADD || opcode == PcodeOp.PTRSUB) {
				System.err.println("      -> used in pointer arithmetic!");
				return true;
			}

			// Check if used as function call argument (could be data access)
			if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
				System.err.println("      -> used in function call!");
				return true;
			}

			// Trace through CAST and COPY operations
			if (opcode == PcodeOp.CAST || opcode == PcodeOp.COPY) {
				Varnode output = use.getOutput();
				if (output != null) {
					System.err.println("      -> tracing through " + use.getMnemonic());
					if (isUsedAsPointerRecursive(output, visited)) {
						return true;
					}
				}
			}

			// Trace through MULTIEQUAL (PHI nodes)
			if (opcode == PcodeOp.MULTIEQUAL) {
				Varnode output = use.getOutput();
				if (output != null) {
					System.err.println("      -> tracing through MULTIEQUAL");
					if (isUsedAsPointerRecursive(output, visited)) {
						return true;
					}
				}
			}
		}

		return false;
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

		// Trace through CAST and COPY operations
		if (defOp.getOpcode() == PcodeOp.CAST || defOp.getOpcode() == PcodeOp.COPY) {
			if (defOp.getNumInputs() > 0) {
				System.err.println("  tracing through " + defOp.getMnemonic());
				return identifyVectorMember(defOp.getInput(0));
			}
		}

		// For MULTIEQUAL (PHI nodes), try the first input
		// This handles cases where value comes from multiple control flow paths
		if (defOp.getOpcode() == PcodeOp.MULTIEQUAL) {
			if (defOp.getNumInputs() > 0) {
				System.err.println("  tracing through MULTIEQUAL (trying first input)");
				VectorMember result = identifyVectorMember(defOp.getInput(0));
				if (result != null) {
					return result;
				}
				// If first doesn't work, try second input
				if (defOp.getNumInputs() > 1) {
					System.err.println("  trying second MULTIEQUAL input");
					return identifyVectorMember(defOp.getInput(1));
				}
			}
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
							// Store the source variable, not the intermediate PTRSUB result
							// This allows isSameVectorBase() to work correctly
							return new VectorMember(memberType, sourceVar);
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
								// Trace back to source variable
								Varnode sourceVar = traceToSourceVariable(baseVarnode);
								System.err.println("LOAD: memberType=" + memberType + " offset=0x" + Long.toHexString(offset));
								System.err.println("LOAD: base=" + baseVarnode);
								System.err.println("LOAD: source=" + sourceVar);
								boolean isVec = (sourceVar != null && isVectorType(sourceVar));
								System.err.println("LOAD: isVector=" + isVec);
								if (isVec) {
									System.err.println(">>> FOUND VECTOR MEMBER VIA LOAD! <<<");
									// Store the source variable, not the intermediate base
									return new VectorMember(memberType, sourceVar);
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
		Varnode bestSoFar = varnode; // Track the best candidate
		Varnode withTypeInfo = null; // Track varnode with type info

		System.err.println("  trace from: " + varnode);

		for (int depth = 0; depth < maxDepth; depth++) {
			System.err.println("    [" + depth + "] " + current);

			// Save if this varnode has vector type info
			boolean hasTypeInfo = hasVectorTypeInfo(current);
			System.err.println("      hasVectorTypeInfo=" + hasTypeInfo);
			if (hasTypeInfo && withTypeInfo == null) {
				withTypeInfo = current;
				System.err.println("      saved withTypeInfo");
			}

			// If it's a free varnode (parameter, local variable), this is best!
			boolean isFreeOrInput = current.isFree() || current.isInput();
			System.err.println("      isFree/isInput=" + isFreeOrInput);
			if (isFreeOrInput) {
				bestSoFar = current;
				System.err.println("      saved as bestSoFar - this is a source variable!");
				// Found the source variable - return it (prefer this over type info)
				System.err.println("      returning source variable");
				return bestSoFar;
			}

			PcodeOp defOp = current.getDef();
			System.err.println("      defOp=" + (defOp != null ? defOp.getMnemonic() : "null"));
			if (defOp == null) {
				// No definition - return best we found
				System.err.println("      no def - returning: " + bestSoFar);
				return bestSoFar;
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
			// Return varnode with type info if we found one, otherwise original
			Varnode result = (withTypeInfo != null) ? withTypeInfo : bestSoFar;
			System.err.println("  trace result (can't trace further): " + result);
			return result;
		}

		// Hit max depth - return varnode with type info if we found one
		Varnode result = (withTypeInfo != null) ? withTypeInfo : bestSoFar;
		System.err.println("  trace result (max depth): " + result);
		return result;
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
