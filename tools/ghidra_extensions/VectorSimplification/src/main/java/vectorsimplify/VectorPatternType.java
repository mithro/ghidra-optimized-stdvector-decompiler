package vectorsimplify;

/**
 * Types of vector operations that can be recognized and simplified.
 */
public enum VectorPatternType {
	/**
	 * vector.size() - (mylast - myfirst) / sizeof(T)
	 */
	SIZE,

	/**
	 * vector.data() - returns myfirst pointer
	 */
	DATA,

	/**
	 * vector.empty() - myfirst == mylast
	 */
	EMPTY,

	/**
	 * vector.capacity() - (myend - myfirst) / sizeof(T)
	 */
	CAPACITY
}
