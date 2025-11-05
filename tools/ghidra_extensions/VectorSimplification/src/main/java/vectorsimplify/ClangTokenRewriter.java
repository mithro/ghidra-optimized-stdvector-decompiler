package vectorsimplify;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import java.util.*;

/**
 * Rewrites decompiled C code by detecting and replacing vector patterns.
 *
 * This works by:
 * 1. Traversing the ClangToken tree structure
 * 2. Finding tokens that correspond to detected vector patterns
 * 3. Replacing those token sequences with simplified C++ idioms
 *
 * This avoids string manipulation by working with Ghidra's structured token tree.
 */
public class ClangTokenRewriter {

    private ClangTokenGroup rootMarkup;
    private List<VectorPattern> patterns;
    private Map<PcodeOp, VectorPattern> opToPattern;
    private Set<PcodeOp> processedOps;

    /**
     * Creates a new token rewriter.
     *
     * @param markup The root ClangTokenGroup from decompilation
     * @param patterns The vector patterns detected in the function
     */
    public ClangTokenRewriter(ClangTokenGroup markup, List<VectorPattern> patterns) {
        this.rootMarkup = markup;
        this.patterns = patterns;
        this.opToPattern = new HashMap<>();
        this.processedOps = new HashSet<>();

        // Build mapping from PcodeOp to pattern
        for (VectorPattern pattern : patterns) {
            opToPattern.put(pattern.getOperation(), pattern);
        }
    }

    /**
     * Rewrites the code by traversing the token tree and replacing patterns.
     *
     * @return Simplified C code as a string
     */
    public String rewrite() {
        if (patterns.isEmpty()) {
            return rootMarkup.toString();
        }

        StringBuilder result = new StringBuilder();
        traverseAndRewrite(rootMarkup, result, 0);
        return result.toString();
    }

    /**
     * Recursively traverses the token tree and rewrites patterns.
     *
     * @param node Current node in the tree
     * @param output StringBuilder to accumulate output
     * @param depth Current depth (for tracking structure)
     */
    private void traverseAndRewrite(ClangNode node, StringBuilder output, int depth) {
        if (node == null) {
            return;
        }

        // Check if this is a token we can analyze
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            PcodeOp op = token.getPcodeOp();

            // Check if this token's operation is part of a pattern we should simplify
            if (op != null && opToPattern.containsKey(op) && !processedOps.contains(op)) {
                VectorPattern pattern = opToPattern.get(op);

                // Mark this operation as processed
                processedOps.add(op);

                // Emit the simplified version
                emitSimplified(pattern, output);
                return;
            }

            // Check if this token is part of a pattern we've already processed
            if (op != null && isPartOfProcessedPattern(op)) {
                // Skip this token - it's part of a pattern we already emitted
                return;
            }

            // Regular token - emit its text
            output.append(token.getText());
            return;
        }

        // For token groups, recursively process children
        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            int numChildren = group.numChildren();

            for (int i = 0; i < numChildren; i++) {
                ClangNode child = group.Child(i);
                traverseAndRewrite(child, output, depth + 1);
            }
        }
    }

    /**
     * Checks if a PcodeOp is part of a pattern that has already been processed.
     */
    private boolean isPartOfProcessedPattern(PcodeOp op) {
        // Check if this op is an input to any processed pattern
        for (PcodeOp processedOp : processedOps) {
            if (isInputTo(op, processedOp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if opToCheck is an input (directly or indirectly) to targetOp.
     */
    private boolean isInputTo(PcodeOp opToCheck, PcodeOp targetOp) {
        if (targetOp == null || opToCheck == null) {
            return false;
        }

        // Check direct inputs
        for (int i = 0; i < targetOp.getNumInputs(); i++) {
            Varnode input = targetOp.getInput(i);
            if (input != null && input.getDef() != null) {
                if (input.getDef().equals(opToCheck)) {
                    return true;
                }
                // Check recursively
                if (isInputTo(opToCheck, input.getDef())) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Emits the simplified version of a vector pattern.
     */
    private void emitSimplified(VectorPattern pattern, StringBuilder output) {
        String vectorName = getVectorName(pattern);

        switch (pattern.getType()) {
            case SIZE:
                output.append("(").append(vectorName).append(").size()");
                break;
            case EMPTY:
                output.append("(").append(vectorName).append(").empty()");
                break;
            case DATA:
                output.append("(").append(vectorName).append(").data()");
                break;
            case CAPACITY:
                output.append("(").append(vectorName).append(").capacity()");
                break;
            default:
                output.append("/* unknown pattern */");
                break;
        }
    }

    /**
     * Extracts the vector variable name from a pattern.
     */
    private String getVectorName(VectorPattern pattern) {
        Varnode base = pattern.getVectorBase();
        if (base == null) {
            return "vec";
        }

        // Try to get the high-level variable representation
        HighVariable highVar = base.getHigh();
        if (highVar != null) {
            String name = highVar.getName();
            if (name != null && !name.isEmpty() && !name.startsWith("UNNAMED")) {
                return name;
            }
        }

        // Fallback: construct a reasonable name
        return "vec";
    }
}
