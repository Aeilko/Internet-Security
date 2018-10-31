package attack.ass07;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class Decoder {

    private List<String> lines;
    private boolean[] input;

    public Decoder(List<String> in){
        this.lines = in;
        this.convertList(in);
        System.out.println(this.input.length);
        this.displayBooleanArray(this.input);
    }

    private void convertList(List<String> in){
        this.input = new boolean[in.size()];
        for(int i = 0; i < in.size(); i++){
            this.input[i] = in.get(i).equals("54");
        }
    }

    public String toASCII(){
        String result = "";

        // We know the text starts with a u, so we are looking for 8 bits representing 117
        int start = -1;
        for(int i = 0; i < this.input.length-7; i++){
            // Calculate int value of 8 bits starting at index i
            char c = this.arrayToChar(this.input, i);
            if(c == 'u'){
                start = i;
                break;
            }
        }

        if(start == -1){
            System.err.println("Can't find 'u' byte");
            return null;
        }

        System.out.println("Found 'u' byte at index " + start);

        // Calculate the remaining bytes
        int chars = (int) Math.floor(((float) (this.input.length-start))/8);

        System.out.println("Remaining chars: " + chars);

        for(int i = 0; i < chars; i++) {
            char c = this.arrayToChar(this.input, start+i*8);
            result += c;
        }

        return result;
    }

    public char arrayToChar(boolean[] in, int startIndex){
        String bits = "";
        for(int i = 7; i >= 0; i--){
            bits += (in[startIndex+i] ? "1" : "0");
        }
        int charInt = Integer.parseInt(bits, 2);
        return (char) charInt;
    }

    public static void displayBooleanArray(boolean[] in){
        String result = "[";
        for(boolean b: in){
            result += b + ", ";
        }
        result += "]";
        System.out.println(result);
    }

    public static void main(String[] args){
        // Read the TTL file
        String filename = "team1-filter-ttl.txt";
        try{
            List<String> lines = Files.readAllLines(Paths.get(filename));
            System.out.println("TTL's: " + lines.size());
            Decoder d = new Decoder(lines);
            System.out.println(d.toASCII());
        }
        catch(Exception e){
            System.out.println("Couldn't read file");
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
    }
}
