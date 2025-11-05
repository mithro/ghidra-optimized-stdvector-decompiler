package vectorsimplify;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Main plugin class for Vector Simplification extension.
 *
 * This plugin registers custom simplification rules with the Ghidra decompiler
 * to recognize std::vector pointer arithmetic patterns and replace them with
 * idiomatic C++ method calls.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "VectorSimplification",
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Simplifies vector operations",
	description = "Transforms std::vector pointer arithmetic into C++ method calls during decompilation"
)
//@formatter:on
public class VectorSimplificationPlugin extends ProgramPlugin {

	/**
	 * Plugin constructor.
	 *
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public VectorSimplificationPlugin(PluginTool tool) {
		super(tool);

		// Register our custom decompiler options
		tool.setMenuGroup(new String[] { "Vector" }, "VectorOps");
	}

	@Override
	public void init() {
		super.init();

		// Note: Ghidra's decompiler simplification rules are registered
		// at the C++ level in the decompiler engine. This plugin provides
		// a framework for the Java side, but actual pcode transformation
		// requires working with Ghidra's ActionDatabase.

		// We'll use the DecompilerActionContext approach instead
	}
}
