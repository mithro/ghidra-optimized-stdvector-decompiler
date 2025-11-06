package vectorsimplify;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal test class to isolate Jython integration issues.
 */
public class SimpleTest {

    /**
     * Test 1: Most basic method - just write to file.
     */
    public void testBasic() {
        try {
            FileWriter fw = new FileWriter("/tmp/simple_test_basic.txt", true);
            fw.write("testBasic() was called at " + System.currentTimeMillis() + "\n");
            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Test 2: Method that returns a simple value.
     */
    public int testWithReturn() {
        try {
            FileWriter fw = new FileWriter("/tmp/simple_test_return.txt", true);
            fw.write("testWithReturn() was called at " + System.currentTimeMillis() + "\n");
            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 42;
    }

    /**
     * Test 3: Method that returns a List.
     */
    public List<String> testWithList() {
        try {
            FileWriter fw = new FileWriter("/tmp/simple_test_list.txt", true);
            fw.write("testWithList() was called at " + System.currentTimeMillis() + "\n");
            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        List<String> result = new ArrayList<>();
        result.add("test");
        return result;
    }

    /**
     * Test 4: Method that returns an empty List (like our problem method).
     */
    public List<String> testWithEmptyList() {
        try {
            FileWriter fw = new FileWriter("/tmp/simple_test_empty_list.txt", true);
            fw.write("testWithEmptyList() was called at " + System.currentTimeMillis() + "\n");
            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new ArrayList<>();
    }

    /**
     * Test 5: Method with a parameter (like HighFunction).
     */
    public List<String> testWithParameter(Object param) {
        try {
            FileWriter fw = new FileWriter("/tmp/simple_test_param.txt", true);
            fw.write("testWithParameter() was called with: " + param + "\n");
            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new ArrayList<>();
    }
}
