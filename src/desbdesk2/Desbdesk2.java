
package desbdesk2;

import com.sun.jdi.VirtualMachine;
import com.sun.jdi.Bootstrap;
import com.sun.jdi.connect.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;

import java.util.Map;
import java.util.List;

import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Desbdesk2{

    // Running remote VM
    private VirtualMachine vm;
    HashSet <String>sources_m;
    HashSet <String>sources_c;
    HashSet <String>sinks_m;
    HashSet <String>sinks_c;
    HashSet <String>flow_c;
    HashSet <String>flow_m;
    String fname;
    String s_var;
    // Thread transferring remote error stream to our error stream
    private Thread errThread = null;

    // Thread transferring remote output stream to our output stream
    private Thread outThread = null;

    // Mode for tracing the Trace program (default= 0 off)
    private int debugTraceMode = 0;
    int r1,r2;
    //  Do we want to watch assignments to fields
    private boolean watchFields = true;

    // Class patterns for which we don't want events
    private String[] excludes = {"java.*", "javax.*", "sun.*",
                                 "com.sun.*","android*","com.android*"};

    /**
     * main
     */
    public static void main(String[] args) {
        //new NewClass1(args);
    }

    /**
     * Parse the command line arguments.
     * Launch target VM.
     * Generate the trace.
     */
    Desbdesk2(String mhh,int i,int j,String sv) 
    {
       r1=i;
       r2=j;
       fname=mhh;
       s_var=sv;
       sources_m=new HashSet<>();
       sinks_m=new HashSet<>();
       sources_c=new HashSet<>();
       sinks_c=new HashSet<>();
       flow_m=new HashSet<>();
       flow_c=new HashSet<>();
       BufferedReader br2=null;  
        try
        {  
          BufferedReader br1=new BufferedReader(new FileReader("sources_a"));
          br2=new BufferedReader(new FileReader("sinks_a")); 
          BufferedReader br3=new BufferedReader(new FileReader("flow"));
          String hh=null;
          while((hh=br1.readLine())!=null)
          {
            String rr[]=hh.split("->");
            sources_c.add(rr[0]);
            sources_m.add(rr[1]);
          }
          while((hh=br2.readLine())!=null)
          {
            String rr[]=hh.split("->");
            sinks_c.add(rr[0]);
            sinks_m.add(rr[1]);  
          }
           while((hh=br3.readLine())!=null)
          {
            String rr[]=hh.split("->");
            flow_c.add(rr[0]);
            flow_m.add(rr[1]);  
          }
          PrintWriter writer = new PrintWriter(System.out);
          Connector connector= findLaunchingConnector();
          Map arguments=connector.defaultArguments();
          Connector.Argument host=(Connector.Argument) arguments.get("hostname");
          Connector.Argument port=(Connector.Argument) arguments.get("port");
          host.setValue("localhost");
          port.setValue("54322");
          System.out.println("loooooooooooooo  "+fname);
          AttachingConnector attacher=(AttachingConnector) connector;
          /*Connector connector= findLaunchingConnector();
          Map arguments=connector.defaultArguments();
          Connector.Argument host=(Connector.Argument) arguments.get("hostname");
          Connector.Argument port=(Connector.Argument) arguments.get("port");
          host.setValue("localhost");
          port.setValue("54322");
          AttachingConnector attacher=(AttachingConnector) connector;*/
          vm=null;
           System.out.println("pppppprerer");
           vm=attacher.attach(arguments);      
           System.out.println("rerer");
           //vm=launcher.launch(arguments);
           generateTrace(writer);           
        }
        catch (Exception e) {  
            e.printStackTrace();
        } 
        
    }
    void generateTrace(PrintWriter writer) {
        vm.setDebugTraceMode(debugTraceMode);
        EventThread eventThread = new EventThread(fname,s_var, r1,r2,sources_c,sources_m,sinks_c,sinks_m,flow_c,flow_m,vm, excludes, writer);
        eventThread.setEventRequests(watchFields);
        eventThread.start();
       // redirectOutput();
        vm.resume();
        try {
            eventThread.join();
      //      errThread.join(); // Make sure output is forwarded
        //    outThread.join(); // before we exit
        } catch (InterruptedException exc) {
            // we don't interrupt
        }
        writer.close();
    }
    
    void redirectOutput() {
        Process process = vm.process();

        // Copy target's output and error to our output and error.
        errThread = new StreamRedirectThread("error reader",
                                             process.getErrorStream(),
                                             System.err);
        outThread = new StreamRedirectThread("output reader",
                                             process.getInputStream(),
                                             System.out);
        errThread.start();
        outThread.start();
    }

    /**
     * Find a com.sun.jdi.CommandLineLaunch connector
     */
   AttachingConnector findLaunchingConnector() {
        List<Connector> connectors = Bootstrap.virtualMachineManager().allConnectors();
        for (Connector connector : connectors) {
            if (connector.name().equals("com.sun.jdi.SocketAttach")) {
                return (AttachingConnector)connector;
            }
        }
        throw new Error("No launching connector");
    }
     /*LaunchingConnector findLaunchingConnector() {
        List<Connector> connectors = Bootstrap.virtualMachineManager().allConnectors();
        for (Connector connector : connectors) {
            if (connector.name().equals("com.sun.jdi.CommandLineLaunch")) {
                return (LaunchingConnector)connector;
            }
        }
        throw new Error("No launching connector");
    }*/
}
