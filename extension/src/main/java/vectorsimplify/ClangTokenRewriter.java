package vectorsimplify;

import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import java.util.*;

/**
 * Rewrites decompiled C code by detecting and replacing vector patterns at the AST level.
 *
 * This works by:
 * 1. Building a map from PcodeOps to their ClangTokens
 * 2. Finding expression boundaries for each pattern
 * 3. Replacing complete expression subtrees with simplified forms
 * 4. Extracting actual variable names from Varnodes
 */
public class ClangTokenRewriter {

    private ClangTokenGroup rootMarkup;
    private List<VectorPattern> patterns;
    private Map<PcodeOp, VectorPattern> opToPattern;
    private Map<PcodeOp, ClangToken> opToToken;
    private Set<ClangNode> nodesToReplace;
    private HighFunction highFunction;

    public ClangTokenRewriter(ClangTokenGroup markup, List<VectorPattern> patterns, HighFunction highFunc) {
        this.rootMarkup = markup;
        this.patterns = patterns;
        this.highFunction = highFunc;
        this.opToPattern = new HashMap<>();
        this.opToToken = new HashMap<>();
        this.nodesToReplace = new HashSet<>();

        // Build mapping from PcodeOp to pattern
        for (VectorPattern pattern : patterns) {
            opToPattern.put(pattern.getOperation(), pattern);
        }

        // Build mapping from PcodeOp to ClangToken and identify expression boundaries
        buildTokenMapping(rootMarkup);
        identifyReplacementNodes();
    }

    /**
     * Recursively build mapping from PcodeOps to ClangTokens.
     */
    private void buildTokenMapping(ClangNode node) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            PcodeOp op = token.getPcodeOp();
            if (op != null) {
                // Store the token for this operation
                opToToken.put(op, token);
            }
        }

        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                buildTokenMapping(group.Child(i));
            }
        }
    }

    /**
     * Identify which ClangNodes should be replaced.
     * For each pattern, find the smallest ClangNode that contains the entire pattern expression.
     */
    private void identifyReplacementNodes() {
        for (VectorPattern pattern : patterns) {
            ClangToken rootToken = opToToken.get(pattern.getOperation());
            if (rootToken != null) {
                ClangNode expressionRoot = findExpressionRoot(rootToken, pattern);
                if (expressionRoot != null) {
                    nodesToReplace.add(expressionRoot);
                }
            }
        }
    }

    /**
     * Find the root of the expression containing this pattern.
     * This walks up the tree to find a suitable boundary (statement, parenthesized expr, etc).
     */
    private ClangNode findExpressionRoot(ClangToken token, VectorPattern pattern) {
        ClangNode current = token;
        ClangNode candidate = token;

        // For DATA patterns, we need special handling because they're often deep in expressions
        if (pattern.getType() == VectorPatternType.DATA) {
            // Walk up until we find a stopping point
            while (current != null) {
                ClangNode parent = current.Parent();
                if (parent == null) {
                    break;
                }

                // Stop at statement boundaries
                if (parent instanceof ClangStatement) {
                    // Use current as candidate (child of statement)
                    break;
                }

                // For DATA, we want to keep walking up through the expression tree
                // to find the largest subtree that ONLY contains this LOAD operation
                // and doesn't mix with other operations

                // Check if parent contains operations other than our pattern
                Set<PcodeOp> parentOps = new HashSet<>();
                collectPcodeOps(parent, parentOps);

                // If parent only contains our pattern's op (and maybe some constants/variables),
                // we can safely replace the parent
                if (parentOps.size() == 1 && parentOps.contains(pattern.getOperation())) {
                    candidate = parent;
                    current = parent;
                } else {
                    // Parent contains other operations - stop here
                    break;
                }
            }
            return candidate;
        }

        // For SIZE/EMPTY patterns: original logic
        while (current != null) {
            ClangNode parent = current.Parent();

            if (parent == null) {
                break;
            }

            // Check if this is a good expression boundary
            if (isExpressionBoundary(parent)) {
                candidate = current;
                break;
            }

            // For SIZE patterns: look for the right-shift operation node
            if (pattern.getType() == VectorPatternType.SIZE) {
                if (parent instanceof ClangTokenGroup) {
                    // Check if this group contains the complete (a - b) >> c expression
                    if (containsCompleteShiftExpression(parent, pattern)) {
                        candidate = parent;
                        break;
                    }
                }
            }

            current = parent;
        }

        return candidate;
    }

    /**
     * Check if a node represents an expression boundary.
     */
    private boolean isExpressionBoundary(ClangNode node) {
        if (node instanceof ClangStatement) {
            return true;
        }
        if (node instanceof ClangFuncProto) {
            return true;
        }
        // ClangTokenGroups with specific types might be boundaries
        return false;
    }

    /**
     * Check if a group contains the complete shift expression for a SIZE pattern.
     */
    private boolean containsCompleteShiftExpression(ClangNode node, VectorPattern pattern) {
        if (!(node instanceof ClangTokenGroup)) {
            return false;
        }

        // Check if this node contains tokens for both the subtraction and shift
        Set<PcodeOp> opsInNode = new HashSet<>();
        collectPcodeOps(node, opsInNode);

        PcodeOp shiftOp = pattern.getOperation();
        if (!opsInNode.contains(shiftOp)) {
            return false;
        }

        // Check if we have the subtraction operation
        if (shiftOp.getNumInputs() >= 1) {
            Varnode subVarnode = shiftOp.getInput(0);
            if (subVarnode != null && subVarnode.getDef() != null) {
                PcodeOp subOp = subVarnode.getDef();
                if (opsInNode.contains(subOp)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Collect all PcodeOps referenced in a subtree.
     */
    private void collectPcodeOps(ClangNode node, Set<PcodeOp> ops) {
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            PcodeOp op = token.getPcodeOp();
            if (op != null) {
                ops.add(op);
            }
        }

        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                collectPcodeOps(group.Child(i), ops);
            }
        }
    }

    /**
     * Rewrite the code by traversing and replacing marked nodes.
     */
    public String rewrite() {
        if (patterns.isEmpty()) {
            return rootMarkup.toString();
        }

        StringBuilder result = new StringBuilder();
        traverseAndRewrite(rootMarkup, result);
        return result.toString();
    }

    /**
     * Recursively traverse and rewrite, replacing marked nodes with simplified code.
     */
    private void traverseAndRewrite(ClangNode node, StringBuilder output) {
        if (node == null) {
            return;
        }

        // Check if this node should be replaced
        if (nodesToReplace.contains(node)) {
            // Find which pattern this node corresponds to
            VectorPattern pattern = findPatternForNode(node);
            if (pattern != null) {
                emitSimplified(pattern, output);
                return; // Skip children - we've replaced this entire subtree
            }
        }

        // Regular processing
        if (node instanceof ClangToken) {
            ClangToken token = (ClangToken) node;
            output.append(token.getText());
            return;
        }

        if (node instanceof ClangTokenGroup) {
            ClangTokenGroup group = (ClangTokenGroup) node;
            for (int i = 0; i < group.numChildren(); i++) {
                traverseAndRewrite(group.Child(i), output);
            }
        }
    }

    /**
     * Find which pattern corresponds to a node we're replacing.
     */
    private VectorPattern findPatternForNode(ClangNode node) {
        Set<PcodeOp> opsInNode = new HashSet<>();
        collectPcodeOps(node, opsInNode);

        // Find a pattern whose operation is in this node
        for (PcodeOp op : opsInNode) {
            if (opToPattern.containsKey(op)) {
                return opToPattern.get(op);
            }
        }

        return null;
    }

    /**
     * Emit the simplified version of a vector pattern.
     */
    private void emitSimplified(VectorPattern pattern, StringBuilder output) {
        String vectorName = getVectorName(pattern);

        switch (pattern.getType()) {
            case SIZE:
                output.append(vectorName).append("->size()");
                break;
            case EMPTY:
                output.append(vectorName).append("->empty()");
                break;
            case DATA:
                output.append(vectorName).append("->data()");
                break;
            case CAPACITY:
                output.append(vectorName).append("->capacity()");
                break;
            default:
                output.append("/* unknown pattern */");
        }
    }

    /**
     * Extract the vector variable name from the pattern's base Varnode.
     */
    private String getVectorName(VectorPattern pattern) {
        Varnode baseVarnode = pattern.getVectorBase();
        if (baseVarnode == null) {
            return "vec";
        }

        // Try to get the high variable
        if (highFunction != null) {
            HighVariable highVar = baseVarnode.getHigh();
            if (highVar != null) {
                // Try to get the symbol name
                HighSymbol symbol = highVar.getSymbol();
                if (symbol != null && symbol.getName() != null) {
                    String name = symbol.getName();
                    // Clean up the name if needed
                    if (!name.isEmpty() && !name.startsWith("UNNAMED")) {
                        return name;
                    }
                }

                // If it's a parameter, try to get parameter name
                if (highVar instanceof HighParam) {
                    HighParam param = (HighParam) highVar;
                    String paramName = param.getName();
                    if (paramName != null && !paramName.isEmpty()) {
                        return paramName;
                    }
                }
            }
        }

        // Try to find a token that references this varnode and extract its text
        String tokenName = findVarnodeName(baseVarnode);
        if (tokenName != null) {
            return tokenName;
        }

        // Fallback: use a generic name
        return "vec";
    }

    /**
     * Try to find the name used for a varnode in the token tree.
     */
    private String findVarnodeName(Varnode varnode) {
        // This is a simplified approach - we'd need to trace back through
        // the token tree to find variable references
        // For now, return null to use other methods
        return null;
    }
}
