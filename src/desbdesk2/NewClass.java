

package desbdesk2;

import com.sun.jdi.*;
import com.sun.jdi.request.*;
import com.sun.jdi.event.*;

import java.util.*;
import java.io.PrintWriter;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

public class NewClass extends Thread {
    boolean inc_s=false;
    HashMap <ThreadReference,pair>line;
    private final VirtualMachine vm;   // Running VM
   // private final String[] excludes;   // Packages to exclude

    static String nextBaseIndent = ""; // Starting indent for next thread
    HashMap <LocalVariable,String>varvl1;
    HashMap <LocalVariable,String>varvl2;
    HashSet <LocalVariable>sensitive;
    HashSet <String>sources_c;
    HashSet <String>sinks_c;
    HashSet <String>sources_m;
    HashSet <String>sinks_m;
    private boolean connected = true;  // Connected to VM
    private boolean vmDied = true;     // VMDeath occurred

    // Maps ThreadReference to ThreadTrace instances
    private Map<ThreadReference, ThreadTrace> traceMap =
       new HashMap<>();

    NewClass( HashSet <String>sr1,HashSet <String>sr2,HashSet <String>sk1,HashSet <String>sk2,VirtualMachine vm, String[] excludes, PrintWriter writer) {
        super("event-handler");
        this.vm = vm;
        line =new HashMap<>();
        varvl2=new HashMap<>();
        sources_c=sr1;
        sinks_c=sk1;
        sources_m=sr2;
        sinks_m=sk2;
        sensitive=new HashSet<>();        
    }

    /**
     * Run the event handling thread.
     * As long as we are connected, get event sets off
     * the queue and dispatch the events within them.
     */
    @Override
    public void run() {
        EventQueue queue = vm.eventQueue();
        while (connected) {
            try {
                EventSet eventSet = queue.remove();
                EventIterator it = eventSet.eventIterator();
                while (it.hasNext()) {
                    handleEvent(it.nextEvent());
                }
                eventSet.resume();
            } catch (InterruptedException exc) {
                // Ignore
            } catch (VMDisconnectedException discExc) {
                handleDisconnectedException();
                break;
            }
        }
    }

    /**
     * Create the desired event requests, and enable
     * them so that we will get events.
     * @param excludes     Class patterns for which we don't want events
     * @param watchFields  Do we want to watch assignments to fields
     */
    void setEventRequests(boolean watchFields) {
        EventRequestManager mgr = vm.eventRequestManager();
        
        // want all exceptions        
        ExceptionRequest excReq = mgr.createExceptionRequest(null,
                                                             true, true);
        // suspend so we can step
        excReq.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        excReq.enable();        
       
        ThreadDeathRequest tdr = mgr.createThreadDeathRequest();
        // Make sure we sync on thread death
        tdr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        tdr.enable();
        ClassPrepareRequest cpr = mgr.createClassPrepareRequest();            
        cpr.addClassFilter("desbdesk2.Test");
        cpr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
        cpr.enable();        
    }

    /**
     * This class keeps context on events in one thread.
     * In this implementation, context is the indentation prefix.
     */
    class ThreadTrace {
        final ThreadReference thread;

        ThreadTrace(ThreadReference thread) {
            this.thread = thread;
            System.out.println("====== " + thread.name() + " ======");
        }


        void methodEntryEvent(MethodEntryEvent event)  { 
            String nm=event.method().name();
            try {
                pair p=line.get(event.thread());
                /*if(nm.equals("getProperty"))
                {*/
                    if(sources_m.contains(nm))
                    {
                        inc_s=true;
                    }
                    else if(sinks_m.contains(nm))
                    {
                        boolean ac=false;
                        for(Value v:event.thread().frame(0).getArgumentValues())
                        {

                           String gn1=v.toString();
                           String gn2=gn1.substring(1,gn1.length()-1);
                           for(LocalVariable bb:sensitive)
                           {
                               if(gn2.equals(varvl1.get(bb))||gn1.equals(varvl1.get(bb)))
                               {
                                   System.err.print(" Data leaked at by "+nm+" "+p.ln);
                                   ac=true;
                               }
                           }
                        }
                        if(ac)
                        {
                            System.err.println();
                        }
                    }  
                //}
            } 
            catch(NullPointerException ex)
            {
                ex.printStackTrace();
            }
            catch (Exception ex) {
                //System.err.println("fault functions is "+nm+"  in  "+event.method().declaringType().name());
           
            }
        }

        void methodExitEvent(MethodExitEvent event)  {
        }

        void fieldWatchEvent(ModificationWatchpointEvent event)  {
            try {
            Field field = event.field();
           // Value value = event.valueToBe();
            System.err.println("modification || Line number="+event.location().lineNumber()+"  "+"Previous value="+event.valueCurrent()+"    "+event.object()+"    " + field.name() + " = " + event.valueToBe());
            } catch (Exception ex) {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
         void fieldAccessEvent(AccessWatchpointEvent event)  {  
                Field field = event.field();
                System.err.println("access || Line number="+event.location().toString()+"  " + field.name()+"    "+field.typeName()+"   "+field.isPrivate()+"    "+event.valueCurrent());          
        }
        void exceptionEvent(ExceptionEvent event) {
            System.out.println("Exception: " + event.exception() +
                    " catch: " + event.catchLocation());

            // Step to the catch
            EventRequestManager mgr = vm.eventRequestManager();
            StepRequest req = mgr.createStepRequest(thread,
                                                    StepRequest.STEP_LINE,
                                                    StepRequest.STEP_OVER);
            req.addCountFilter(1);  // next step only
            req.setSuspendPolicy(EventRequest.SUSPEND_ALL);           
            req.enable();
        }
        void breakpointEvent(BreakpointEvent event){
            try 
            {
                pair pr=new pair();
                pr.cname=event.location().declaringType().name();
                pr.ln=event.location().lineNumber();        
                line.put(event.thread(),pr);
                EventRequestManager mgr = vm.eventRequestManager(); 
                if(event.location().lineNumber()==27)
                {
                    for(LocalVariable v:event.location().method().variables())
                    {
                        varvl2.put(v,null);
                        if("t1".equals(v.name()))
                        {
                            sensitive.add(v);
                        }
                    }
                    StackFrame sf=event.thread().frame(0);
                    for(LocalVariable v:sf.visibleVariables())
                    {
                        varvl2.put(v,sf.getValue(v).toString());
                    }
                    varvl1=new HashMap<>(varvl2);
                    System.out.println("1st breakpoint hit at=== "+event.location().lineNumber());                                     
                    StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                    st.addCountFilter(1);
                    st.setSuspendPolicy(EventRequest.SUSPEND_ALL);
                    st.enable(); 
                    sources_c.addAll(sinks_c);
                    for(String cs:sources_c)
                    {
                        MethodEntryRequest menr = mgr.createMethodEntryRequest();
                        menr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
                        menr.addClassFilter(cs);
                        menr.addThreadFilter(event.thread());
                        menr.enable();
                    }
                }
                else
                {   
                    mgr.deleteEventRequest(mgr.stepRequests().get(0));
                    for(MethodEntryRequest mr:mgr.methodEntryRequests())
                    {
                        mgr.deleteEventRequest(mr);
                    }
                }
            } catch (Exception ex) {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }                    
        }
       /* void checkmodified(ThreadReference th)
        {
            boolean m=false;
            for(LocalVariable v:varvl1.keySet())
            {
                String hh=varvl1.get(v);
                if((hh!=null)&&(!hh.equals(varvl2.get(v))))
                {
                    System.err.print(v.name()+" "+(line.get(th).ln-1));
                    m=true;
                }
            }
        }
        void checkaccessed()
        {
            
        }*/
        void stepEvent(StepEvent event)  {            
            try {
         //       System.out.println(sensitive.size());
                // Adjust call depth 
                line.get(event.thread()).ln=event.location().lineNumber();
             // System.out.println(event.thread().frame(0).toString()+" Steeeeeeeeeeeeep eventttttttttttttttttttttttttttttttttttt at== "+event.location().lineNumber());                
                EventRequestManager mgr = vm.eventRequestManager();
                mgr.deleteEventRequest(event.request());
                //System.err.print("Stepevent  "+event.thread().frame(0).location());
                StackFrame sf=event.thread().frame(0);
                for(LocalVariable v:sf.visibleVariables())
                {
                    //System.err.print(v.name()+":"+sf.getValue(v)+" ");
                       // varvl1.put(v,sf.getValue(v).toString());
                    if(!sf.getValue(v).toString().equals(varvl1.get(v)))
                    {    
                        if(varvl1.containsValue(sf.getValue(v).toString()))
                        {
                            for(LocalVariable mm:sensitive)
                            {
                                String tpp=varvl1.get(mm);
                                if((tpp!=null)&&(tpp.equals(sf.getValue(v).toString())))
                                {
                                    System.err.println(mm.name()+"->"+v.name()+" "+(line.get(event.thread()).ln-1));
                                    sensitive.add(v);
                                }
                            }
                        }
                        else if(sensitive.contains(v))
                        {
                            sensitive.remove(v);
                        }
                        if(inc_s)
                        {
                            sensitive.add(v);
                            inc_s=false;
                        }
                        varvl1.put(v,sf.getValue(v).toString());
                    }
                }
                //System.err.println();
                /*for(LocalVariable v:varvl1.keySet())
                {
                        System.err.print(" "+v.name()+":"+varvl1.get(v));
                }
                System.err.println();*/
                
                //checkmodified(event.thread());
                //checkaccessed();
                StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                st.addCountFilter(1);
                st.setSuspendPolicy(EventRequest.SUSPEND_ALL);
                st.enable(); 
                varvl2=new HashMap<>(varvl1);
            } catch (Exception ex) {
               System.err.println("errorrrrrrr at "+event.location());
            }
        }

        void threadDeathEvent(ThreadDeathEvent event)  {
            System.out.println("====== " + thread.name() + " end ======");
        }
    }

    /**
     * Returns the ThreadTrace instance for the specified thread,
     * creating one if needed.
     */
    ThreadTrace threadTrace(ThreadReference thread) {
        ThreadTrace trace = traceMap.get(thread);
        if (trace == null) {
            trace = new ThreadTrace(thread);
            traceMap.put(thread, trace);
        }
        return trace;
    }

    /**
     * Dispatch incoming events
     */
    private void handleEvent(Event event) {
        if (event instanceof ExceptionEvent) {
            exceptionEvent((ExceptionEvent)event);
        } else if (event instanceof ModificationWatchpointEvent) {
            fieldWatchEvent((ModificationWatchpointEvent)event);
        } else if (event instanceof  AccessWatchpointEvent) {
            fieldAccessEvent((AccessWatchpointEvent)event);
        } 
          else if (event instanceof MethodEntryEvent) {
            methodEntryEvent((MethodEntryEvent)event);
        } else if (event instanceof MethodExitEvent) {
            methodExitEvent((MethodExitEvent)event);
        } else if (event instanceof StepEvent) {
            stepEvent((StepEvent)event);
        } else if (event instanceof ThreadDeathEvent) {
            threadDeathEvent((ThreadDeathEvent)event);
        } else if (event instanceof ClassPrepareEvent) {
            classPrepareEvent((ClassPrepareEvent)event);
        } else if (event instanceof VMStartEvent) {
            vmStartEvent((VMStartEvent)event);
        } else if (event instanceof VMDeathEvent) {
            vmDeathEvent((VMDeathEvent)event);
        } else if (event instanceof VMDisconnectEvent) {
            vmDisconnectEvent((VMDisconnectEvent)event);
        } 
        else if (event instanceof BreakpointEvent) {
            breakpointEvent((BreakpointEvent)event);
        }
          else {
            
            throw new Error("Unexpected event type ");
        }
    }

    /***
     * A VMDisconnectedException has happened while dealing with
     * another event. We need to flush the event queue, dealing only
     * with exit events (VMDeath, VMDisconnect) so that we terminate
     * correctly.
     */
    synchronized void handleDisconnectedException() {
        EventQueue queue = vm.eventQueue();
        while (connected) {
            try {
                EventSet eventSet = queue.remove();
                EventIterator iter = eventSet.eventIterator();
                while (iter.hasNext()) {
                    Event event = iter.nextEvent();
                    if (event instanceof VMDeathEvent) {
                        vmDeathEvent((VMDeathEvent)event);
                    } else if (event instanceof VMDisconnectEvent) {
                        vmDisconnectEvent((VMDisconnectEvent)event);
                    }
                }
                eventSet.resume(); // Resume the VM
            } catch (InterruptedException exc) {
                // ignore
            }
        }
    }

    private void vmStartEvent(VMStartEvent event)  {
         System.out.println("-- VM Started --");         
    }

    // Forward event for thread specific processing
    private void methodEntryEvent(MethodEntryEvent event)  {
         threadTrace(event.thread()).methodEntryEvent(event);
    }

    // Forward event for thread specific processing
    private void methodExitEvent(MethodExitEvent event)  {
         threadTrace(event.thread()).methodExitEvent(event);
    }

    // Forward event for thread specific processing
    private void stepEvent(StepEvent event)  {
         threadTrace(event.thread()).stepEvent(event);
    }

    // Forward event for thread specific processing
    private void fieldWatchEvent(ModificationWatchpointEvent event)  {
         threadTrace(event.thread()).fieldWatchEvent(event);
    }    
    private void fieldAccessEvent(AccessWatchpointEvent event)  {
         threadTrace(event.thread()).fieldAccessEvent(event);
         
    }
    private void breakpointEvent(BreakpointEvent event)  {
         threadTrace(event.thread()).breakpointEvent(event);  
         
    }        
    void threadDeathEvent(ThreadDeathEvent event)  {
        ThreadTrace trace = traceMap.get(event.thread());
        if (trace != null) {  // only want threads we care about
            trace.threadDeathEvent(event);   // Forward event
        }
    }

    /**
     * A new class has been loaded.
     * Set watchpoints on each of its fields
     */
    private void classPrepareEvent(ClassPrepareEvent event)  {      

        try {      
            EventRequestManager mgr = vm.eventRequestManager();
            System.out.print("class prepared  ");
            for(Location ln:event.referenceType().allLineLocations())
            {
                System.out.print(ln.lineNumber()+" ");
            }System.out.println();
            /*System.err.println(event.thread());
            MethodEntryRequest menr = mgr.createMethodEntryRequest();
            //menr.addCountFilter(5);
            menr.setSuspendPolicy(EventRequest.SUSPEND_ALL);
            // menr.addClassFilter("debdesk.*");
            menr.addThreadFilter(event.thread());
            menr.enable();
            MethodExitRequest mexr = mgr.createMethodExitRequest();
            mexr.setSuspendPolicy(EventRequest.SUSPEND_NONE);
            // mexr.addClassFilter("debdesk.*");
            mexr.addThreadFilter(event.thread());
            mexr.enable();
            int i=event.referenceType().visibleFields().size();
            int j=event.referenceType().fields().size();
            System.out.println("class preparedddddddd "+i+" "+j
            +" "+event.referenceType().name());*/
            try {
                /*StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                st.addCountFilter(5);
                st.enable();*/
                ArrayList <Location>l1=(ArrayList <Location>) event.referenceType().locationsOfLine(27);
                ArrayList <Location>l2=(ArrayList <Location>) event.referenceType().locationsOfLine(36);
                if((l1.size()+l2.size())>2)
                {
                    System.err.println("more than one location possible");
                }
                BreakpointRequest b1=mgr.createBreakpointRequest(l1.get(0));
                b1.setSuspendPolicy(EventRequest.SUSPEND_ALL);
                b1.enable();
                BreakpointRequest b2=mgr.createBreakpointRequest(l2.get(0));
                b2.setSuspendPolicy(EventRequest.SUSPEND_ALL);
                b2.enable();
                //  event.referenceType().fieldByName(nextBaseIndent);
            } catch (AbsentInformationException ex) {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }
            List<Field> fields = event.referenceType().visibleFields();
            for (Field field : fields) {
                ModificationWatchpointRequest req =
                        mgr.createModificationWatchpointRequest(field);
                AccessWatchpointRequest rw =
                        mgr.createAccessWatchpointRequest(field);
                //  req.addClassFilter("debdesk.*");
                req.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                // req.enable();
                rw.addClassFilter("debdesk.*");
                // rw.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                //rw.enable();
            }
        } catch (AbsentInformationException ex) {
            Logger.getLogger(NewClass.class.getName()).log(Level.SEVERE, null, ex);
        }       
    }
    private void exceptionEvent(ExceptionEvent event) {
        ThreadTrace trace = traceMap.get(event.thread()); 
        if (trace != null) {  // only want threads we care about
            trace.exceptionEvent(event);      // Forward event
        }
    }

    public void vmDeathEvent(VMDeathEvent event) {
        vmDied = true;
        System.out.println("-- The application exited --");
    }

    public void vmDisconnectEvent(VMDisconnectEvent event) {
        connected = false;
        if (!vmDied) {
            System.out.println("-- The application has been disconnected --");
        }
    }
    class pair{
        String cname;
        int ln;
    }
}
