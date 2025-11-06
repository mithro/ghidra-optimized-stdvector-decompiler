package vectorsimplify;

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Custom decompiler that simplifies std::vector operations.
 *
 * This decompiler analyzes the pcode representation to detect vector patterns
 * and provides simplified C++ code with idiomatic method calls instead of
 * low-level pointer arithmetic.
 *
 * Usage:
 * <pre>
 * VectorSimplifyingDecompiler decompiler = new VectorSimplifyingDecompiler();
 * decompiler.openProgram(program);
 * DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
 * String simplified = decompiler.getSimplifiedC(results);
 * </pre>
 */
public class VectorSimplifyingDecompiler extends DecompInterface {

	private VectorPatternMatcher patternMatcher;
	private boolean simplificationEnabled = true;
	private Map<Function, String> simplifiedCodeCache;

	public VectorSimplifyingDecompiler() {
		super();
		this.patternMatcher = new VectorPatternMatcher();
		this.simplifiedCodeCache = new HashMap<>();
	}

	/**
	 * Decompile a function and cache simplified code if patterns are found.
	 */
	@Override
	public DecompileResults decompileFunction(Function func, int timeoutSecs, TaskMonitor monitor) {
		// Get the standard decompilation
		DecompileResults results = super.decompileFunction(func, timeoutSecs, monitor);

		if (!simplificationEnabled || !results.decompileCompleted()) {
			return results;
		}

		// Get the high function for analysis
		HighFunction highFunc = results.getHighFunction();
		if (highFunc == null) {
			return results;
		}

		try {
			// Analyze and identify vector patterns
			List<VectorPattern> patterns = patternMatcher.findVectorPatterns(highFunc);

			// Get original code
			DecompiledFunction decompiledFunc = results.getDecompiledFunction();
			String originalCode = decompiledFunc != null ? decompiledFunc.getC() : "";

			if (patterns.isEmpty()) {
				// No patterns found - cache original code
				simplifiedCodeCache.put(func, originalCode);
				return results;
			}

			// Report what we found
			System.out.println("[VectorSimplification] Simplifying " + patterns.size() +
				" vector patterns in " + func.getName());

			// Get the markup for AST-level rewriting
			ClangTokenGroup markup = results.getCCodeMarkup();
			if (markup == null) {
				// No markup available - use original code
				simplifiedCodeCache.put(func, originalCode);
				return results;
			}

			// Apply AST-level transformations
			ClangTokenRewriter rewriter = new ClangTokenRewriter(markup, patterns, highFunc);
			String simplifiedCode = rewriter.rewrite();

			// Cache the simplified code
			simplifiedCodeCache.put(func, simplifiedCode);

		}
		catch (Exception e) {
			System.err.println("[VectorSimplification] Error in " + func.getName() +
				": " + e.getMessage());
			e.printStackTrace();
		}

		return results;
	}

	/**
	 * Gets the simplified C code for a decompiled function.
	 *
	 * Call this after decompileFunction() to get code with vector simplifications.
	 * If no simplifications were applied, returns the original code.
	 *
	 * @param results The results from decompileFunction()
	 * @return Simplified C code, or original code if no simplifications applied
	 */
	public String getSimplifiedC(DecompileResults results) {
		if (results == null || !results.decompileCompleted()) {
			return "";
		}

		Function func = results.getFunction();
		if (simplifiedCodeCache.containsKey(func)) {
			return simplifiedCodeCache.get(func);
		}

		// No cached code - return original
		DecompiledFunction decompiledFunc = results.getDecompiledFunction();
		if (decompiledFunc != null) {
			return decompiledFunc.getC();
		}

		return "";
	}

	/**
	 * Gets the simplified C code for a function, decompiling it if necessary.
	 *
	 * @param func The function to decompile
	 * @param timeoutSecs Timeout in seconds
	 * @param monitor Task monitor
	 * @return Simplified C code
	 */
	public String getSimplifiedC(Function func, int timeoutSecs, TaskMonitor monitor) {
		DecompileResults results = decompileFunction(func, timeoutSecs, monitor);
		return getSimplifiedC(results);
	}

	/**
	 * Clears the simplified code cache.
	 */
	public void clearCache() {
		simplifiedCodeCache.clear();
	}

	public void setSimplificationEnabled(boolean enabled) {
		this.simplificationEnabled = enabled;
	}

	public boolean isSimplificationEnabled() {
		return simplificationEnabled;
	}
}
