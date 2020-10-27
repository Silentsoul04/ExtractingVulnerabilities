package Extracting_Vulnerabilities;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Scanner;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

/**
 *
 * @author mannatsharma
 */
public class Extracting_Vulnerabilities {

    private static final int NUM_CWE = 25;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        run();
    }

    public static void run() {
        String[][] cwe = getCWENameURL(); // "CWE-862", "name", "url"
        String[] desc = new String[NUM_CWE];
        for (int cweIndex = 0; cweIndex < NUM_CWE; cweIndex++) {
            String[] num = cwe[cweIndex][0].split("-");
            String url2 = "https://cwe.mitre.org/data/definitions/" + num[1] + ".html";
            desc[cweIndex] = getDesc(url2);
        }
//        String[] relatedCWE = getRelated(); // unfinished

        // File creation and checking
        String filename = "src/CWEdata.txt";
        boolean fileExists = new File(filename).isFile(); // to check if file exists
        boolean[] changes = new boolean[25];
        try {
            if (fileExists) { // file exists, comparing new and saved data 
                String line;
                BufferedReader br = new BufferedReader(new FileReader(filename));
                int i = 0;
                while ((line = br.readLine()) != null) {
                    if (!line.equals(cwe[i][0] + " " + cwe[i][1])) {
                        changes[i] = true;
                    }
                    line = br.readLine();
                    if (changes[i] == false && !line.equals(desc[i])) {
                        changes[i] = true;
                    }
                    line = br.readLine();
                    i++;  
                }
                br.close();
                boolean changed = false;
                for (i = 0; i < NUM_CWE; i++) {
                    if (changes[i] == true) {
                        System.out.println("Change found for: " + cwe[i][0] + " in new data");
                        changed = true;
                    }
                }
                if (changed) {
                    Scanner scanIn = new Scanner(System.in);
                    System.out.println("Do you want to save the new data?");
                    String input = "";
                    while (!input.equals("y") && !input.equals("yes") && !input.equals("n") && !input.equals("no") && !input.equals("1") && !input.equals("0")) {
                        System.out.print("  1: yes 0: no >> ");
                        input = scanIn.next();
                    }
                    if (input.equals("y") || input.equals("yes") || input.equals("1")) {
                        filename = "src/newCWEdata.txt";
                    } else {
                        filename = "noWrite";
                    }
                } else {
                    System.out.println("Data up-to-date!");
                }
            }
            // file doesn't exist, creating file with data
            if (!filename.equals("noWrite")) {
                BufferedWriter bw = new BufferedWriter(new FileWriter(filename));
                for (int i = 0; i < NUM_CWE; i++) {
                    bw.write(cwe[i][0] + " " + cwe[i][1]);
                    bw.newLine();
                    bw.write(desc[i]);
                    bw.newLine();
                    bw.newLine();
                }
                bw.close();
                System.out.println("Data saved in newCWEdata.txt");
            }
        } catch (IOException ioe) {
            System.out.println(ioe.getMessage());
        }
        System.out.println("");
    }

    /*
    Method still needs work
     */
    public static String[] getRelated() {
        String[] related = new String[50];
        Arrays.fill(related, "");
        Document doc;
        try {
            doc = Jsoup.connect("https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html").get();
            org.jsoup.select.Elements rows = doc.select("div[class=tabledetail]");
            org.jsoup.select.Elements rows3 = rows.select("[style=font-size:90%]");
//[class=tabledetail]  [style=font-size:90%]
//[id=Detail], [border=2], [cellpadding=2], [cellspacing=2]
//            org.jsoup.select.Elements rows = doc.select("[class=tabledetail],  [style=font-size:90%]");
//            org.jsoup.select.Elements rows3 = rows.select("[id=Detail], [border=2], [cellpadding=2], [cellspacing=2]");

            int countFill = 0;
            int i = 0;
            for (org.jsoup.nodes.Element row : rows3) {
                org.jsoup.select.Elements columns = row.select("td");
                for (org.jsoup.nodes.Element column : columns) {
                    if (column.text().substring(0, 3).equals("CWE")) {
                        related[i] += column.text() + ", ";
                        System.out.println(column.text() + "\n");
                    }
                }
//                if (related[i].isEmpty()) {
//                    
//                }
//                if (related[i].isEmpty() && countFill == 0) {
//                    
//                } else if (related[i].isEmpty() && countFill == 1) {
//                    
//                } else if (related[i].isEmpty() && countFill == 2) {
//                    
//                }
                System.out.println("--");
                i++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return related;
    }

    /*
    Gets description for each CWE
     */
    public static String getDesc(String url) {
        String desc = "";
        Document doc;
        try {
            //Get Document object after parsing the html from given url.
            doc = Jsoup.connect(url).get();
            Element link = doc.select("div[class=indent]").first();
            desc = link.text();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return desc;
    }

    /*
    Gets CWE, it's name, and it's url for use later
     */
    public static String[][] getCWENameURL() {
        String[][] cwe = new String[NUM_CWE][3]; // "CWE-862", "Missing Authorization", "url"
        for (int row = 0; row < NUM_CWE; row++) {
            cwe[row][2] = "https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html";
        }
        Document doc;
        try {
            //Get Document object after parsing the html from given url.
            doc = Jsoup.connect("https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html").get();
            Element rows = doc.select("table[id=Detail]").first();
            Iterator<Element> ite = rows.select("td").iterator();
            int i = 0;
            while (i<NUM_CWE && ite.hasNext()) {
                ite.next(); // to skip rank
                cwe[i][0] = ite.next().text(); // no error checking, adds cwe
                cwe[i][1] = ite.next().text(); // no error checking, adds name
                cwe[i][2] += cwe[i][0]; // adds url
                ite.next(); // no error checking, to skip score
                i++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return cwe;
    }

    public static void print(String string) {
        System.out.println(string);
    }
}
