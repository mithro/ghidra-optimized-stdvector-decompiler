package vectorsimplify;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Represents a recognized vector operation pattern.
 */
public class VectorPattern {
	private VectorPatternType type;
	private PcodeOp operation;
	private Varnode vectorBase;
	private long elementSizeShift;

	public VectorPattern(VectorPatternType type, PcodeOp operation, Varnode vectorBase,
			long elementSizeShift) {
		this.type = type;
		this.operation = operation;
		this.vectorBase = vectorBase;
		this.elementSizeShift = elementSizeShift;
	}

	public VectorPatternType getType() {
		return type;
	}

	public PcodeOp getOperation() {
		return operation;
	}

	public Varnode getVectorBase() {
		return vectorBase;
	}

	public long getElementSizeShift() {
		return elementSizeShift;
	}

	/**
	 * Get the element size based on the shift amount.
	 * shift=1 -> 2 bytes, shift=2 -> 4 bytes, shift=3 -> 8 bytes
	 */
	public int getElementSize() {
		return 1 << (int) elementSizeShift;
	}

	@Override
	public String toString() {
		return String.format("VectorPattern{type=%s, elementSize=%d, op=%s}", type,
			getElementSize(), operation.getSeqnum());
	}
}
