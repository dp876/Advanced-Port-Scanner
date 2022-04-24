import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

class StreamGobbler extends Thread {

    protected InputStream is;
    protected String type;
    protected List<String> outputLines;

    StreamGobbler(InputStream is, String type) {
        this.is = is;
        this.type = type;
        outputLines = new ArrayList<>();
    }

    public List<String> getOutputLines() {
        return outputLines;
    }

    @Override
    public void run() {
        try {
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;
            while((line = br.readLine()) != null) {
                outputLines.add(line);
            }
        } catch(IOException ex) {
        	
        }
    }
}
