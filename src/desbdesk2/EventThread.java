

package desbdesk2;

import com.sun.jdi.*;
import com.sun.jdi.request.*;
import com.sun.jdi.event.*;

import java.util.*;
import java.io.PrintWriter;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EventThread extends Thread {
    String s_var;
    String last_Sensitive_Source_Calls="";
    String fname;
    LocalVariable flown_to_var=null;
    int Sensitive_Source_Calls_line_no=0;
    long days, seconds, minutes, hours, uptime;
    HashMap <ThreadReference,pair>line;
    private final VirtualMachine vm;   // Running VM
   // private final String[] excludes;   // Packages to exclude
    int b1,b2;
    static String nextBaseIndent = ""; // Starting indent for next thread
    HashMap <LocalVariable,Value>variables_new_value;
    Value modified_class_variable_value;
    int lineJustExecuted;
    String modified_class_variable_name="";
    HashMap <String,Value>last_class_var_access;
    HashMap <LocalVariable,Value>variables_old_value;
    HashMap <LocalVariable,String>taint_information_local;
    HashMap <String,String>taint_information_class;
    HashSet <LocalVariable>sensitive_local_variables;
    HashSet <String>sensitive_class_variables;
    HashSet <String>sensitive_source_classes;
    HashSet <String>sensitive_sink_classes;
    HashSet <String>sensitive_source_methods;
    HashSet <String>sensitive_sink_methods;
    HashSet <String>flow_classes;
    HashSet <String>flow_methods;
    private boolean connected = true;  // Connected to VM
    private boolean vmDied = true;     // VMDeath occurred

    // Maps ThreadReference to ThreadTrace instances
    private Map<ThreadReference, ThreadTrace> traceMap =
       new HashMap<>();

    EventThread(String yy, String hhp,int i, int j,HashSet <String>sr1,HashSet <String>sr2,HashSet <String>sk1,HashSet <String>sk2,HashSet <String>sk3,HashSet <String>sk4,VirtualMachine vm, String[] excludes, PrintWriter writer) {
        super("event-handler");
        this.vm = vm;
        line =new HashMap<>();
        variables_old_value=new HashMap<>();
        taint_information_local=new HashMap<>();
        taint_information_class=new HashMap<>();        
        last_class_var_access=new HashMap<>();
        sensitive_source_classes=sr1;
        fname=yy;
        b1=i;
        b2=j;
        s_var=hhp;
        System.out.println("got breakpoints "+i+" and"+j);
        sensitive_sink_classes=sk1;
        sensitive_source_methods=sr2;
        sensitive_sink_methods=sk2;
        sensitive_local_variables=new HashSet<>();  
        sensitive_class_variables=new HashSet<>();  
        flow_classes=sk3;
        flow_methods=sk4;        
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
        cpr.addClassFilter("*."+fname);
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
            
            String currentMethodName=event.method().name();
            try {
                pair p=line.get(event.thread());
                /*if(nm.equals("getProperty"))
                {*/
                    if(sensitive_source_methods.contains(currentMethodName))
                    {
                        last_Sensitive_Source_Calls+=currentMethodName+" ";
                        Sensitive_Source_Calls_line_no=p.ln;
                    }                    
                    else if(sensitive_sink_methods.contains(currentMethodName))
                    {
                        boolean ac=false;
                        for(Value v:event.thread().frame(0).getArgumentValues())
                        {
                            if(v!=null)
                            {
                                for(LocalVariable bb:sensitive_local_variables)
                                {
                                    if(v.equals(variables_new_value.get(bb)))
                                    {
                                        System.err.println(" Data leaked at "+p.ln+" by "+currentMethodName);
                                        System.err.print(bb.name()+" was tainted by "+taint_information_local.get(bb));
                                        ac=true;
                                        break;
                                    }
                                }                                
                            }
                        }
                        if(ac)
                        {
                            System.err.println();
                        }
                    } 
                    else if(flow_methods.contains(currentMethodName))
                    {
                        for(Value v:event.thread().frame(0).getArgumentValues())
                        {
                            if((v!=null)&&(event.thread().frame(0).thisObject()!=null))
                            {
                                
                                String tmpn=event.thread().frame(0).thisObject().toString();
                                String thatClassVar="";
                                for(String name:last_class_var_access.keySet())
                                {
                                    if(tmpn.equals(last_class_var_access.get(name).toString()))
                                    {
                                        thatClassVar=name;
                                        break;
                                    }
                                }
                                if(!thatClassVar.equals(""))
                                {
                                    if(last_class_var_access.containsValue(v))
                                    {
                                        for(String name:last_class_var_access.keySet())
                                        {
                                            if(!name.equals(thatClassVar))
                                            {
                                                Value val=last_class_var_access.get(name);
                                                if(v.equals(val))
                                                {
                                                    if(sensitive_class_variables.contains(name))
                                                    {
                                                        sensitive_class_variables.add(thatClassVar);
                                                    }                                              
                                                    taint_information_class.put(thatClassVar, taint_information_class.get(thatClassVar)+" "+taint_information_class.get(name)+" "+name+":line-"+p.ln);                                                                                                     
                                                }
                                            }
                                        }
                                    }
                                    else if(variables_new_value.containsValue(v))
                                    {
                                        for(LocalVariable bb:variables_new_value.keySet())
                                        {
                                            if(v.equals(variables_new_value.get(bb)))
                                            {
                                                if(sensitive_local_variables.contains(bb))
                                                {
                                                    sensitive_class_variables.add(thatClassVar);
                                                }                                              
                                                taint_information_class.put(thatClassVar, taint_information_class.get(thatClassVar)+" "+taint_information_local.get(bb)+" "+bb.name()+":line-"+p.ln);
                                                break;                                                                                                    
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    if(last_class_var_access.containsValue(v))
                                    {
                                        for(String name:last_class_var_access.keySet())
                                        {
                                            Value val=last_class_var_access.get(name);
                                            if(v.equals(val))
                                            {
                                                String var_o=event.thread().frame(0).thisObject().toString();
                                                for(LocalVariable tm:variables_new_value.keySet())
                                                {
                                                    if((variables_new_value.get(tm)!=null)&&variables_new_value.get(tm).toString().equals(var_o))
                                                    {
                                                        if(sensitive_class_variables.contains(name))
                                                        {
                                                            sensitive_local_variables.add(tm);
                                                        }                                              
                                                        taint_information_local.put(tm, taint_information_local.get(tm)+" "+taint_information_class.get(name)+" "+name+":line-"+p.ln);
                                                        break;
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    else if(variables_new_value.containsValue(v))
                                    {
                                        for(LocalVariable bb:variables_new_value.keySet())
                                        {
                                            if(v.equals(variables_new_value.get(bb)))
                                            {
                                                String var_o=event.thread().frame(0).thisObject().toString();
                                                for(LocalVariable tm:variables_new_value.keySet())
                                                {
                                                    if((variables_new_value.get(tm)!=null)&&variables_new_value.get(tm).toString().equals(var_o))
                                                    {
                                                        if(sensitive_local_variables.contains(bb))
                                                        {
                                                            sensitive_local_variables.add(tm);
                                                        }                                              
                                                        taint_information_local.put(tm, taint_information_local.get(tm)+" "+taint_information_local.get(bb)+" "+bb.name()+":line-"+p.ln);
                                                        break;
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }     
                                }
                            }
                        }
                    }
                //}
            } 
            catch(NullPointerException ex)
            {
                ex.printStackTrace();
            }            
            catch (Exception ex) {
                System.err.println("fault functions is "+currentMethodName+"  in  "+event.method().declaringType().name()+" "+ex.toString());           
            }
        }

        void methodExitEvent(MethodExitEvent event)  {
        }

        void fieldWatchEvent(ModificationWatchpointEvent event)  {
            try 
            {
                Field field = event.field();
                modified_class_variable_name=field.name();
                modified_class_variable_value=event.valueToBe();
               // Value value = event.valueToBe();
               // System.err.println("modification || Line number="+event.location().lineNumber()+"  "+"Previous value="+event.valueCurrent()+"    "+event.object()+"    " + field.name() + " = " + event.valueToBe());                                              
            } 
            catch (Exception ex) 
            {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
         void fieldAccessEvent(AccessWatchpointEvent event)  {  
                Field field = event.field();
                
                //System.err.println("access || Line number="+event.location().toString()+"  " + field.name()+"    "+field.typeName()+"   "+field.isPrivate()+"    "+event.valueCurrent());          
                last_class_var_access.put(field.name(), event.valueCurrent());
         }
        void exceptionEvent(ExceptionEvent event) {
            System.err.println("Exception: " + event.exception() +
                    " catch: " + event.toString());
/*
            // Step to the catch
            EventRequestManager mgr = vm.eventRequestManager();
            StepRequest req = mgr.createStepRequest(thread,
                                                    StepRequest.STEP_LINE,
                                                    StepRequest.STEP_OVER);
            req.addCountFilter(1);  // next step only
            req.setSuspendPolicy(EventRequest.SUSPEND_ALL);           
            req.enable();*/
        }
        void breakpointEvent(BreakpointEvent event){
            try 
            {
               uptime = System.currentTimeMillis();

               days = TimeUnit.MILLISECONDS.toDays(uptime);
               uptime -= TimeUnit.DAYS.toMillis(days);

               hours = TimeUnit.MILLISECONDS.toHours(uptime);
               uptime -= TimeUnit.HOURS.toMillis(hours);

               minutes = TimeUnit.MILLISECONDS.toMinutes(uptime);
               uptime -= TimeUnit.MINUTES.toMillis(minutes);

               seconds = TimeUnit.MILLISECONDS.toSeconds(uptime);
               
               
                EventRequestManager mgr = vm.eventRequestManager(); 
                
                List<Field> fields = event.location().declaringType().fields();
                for (Field field : fields) 
                {
                    ModificationWatchpointRequest req = mgr.createModificationWatchpointRequest(field);
                    AccessWatchpointRequest rw = mgr.createAccessWatchpointRequest(field);
                    System.out.println(field.name()+"  is class variable");
                    req.addClassFilter(event.location().declaringType());
                    rw.addClassFilter(event.location().declaringType()); 
                    
                    req.addThreadFilter(event.thread());
                    rw.addThreadFilter(event.thread());
                    
                    //  req.addClassFilter("debdesk.*");
                    req.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                    rw.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                    req.enable();
                    // rw.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                    rw.enable();
                }
                pair pr=new pair();
                lineJustExecuted=b1;
                pr.cname=event.location().declaringType().name();
                pr.ln=event.location().lineNumber();        
                line.put(event.thread(),pr);
                System.out.print("List of local variables: ");
                    for(LocalVariable v:event.location().method().variables())
                    {
                        variables_old_value.put(v,null);
                        taint_information_local.put(v,"");
                        System.out.print(v.name()+" ");
                        for(String ss:s_var.split(","))
                        {
                            if(ss.equals(v.name()))
                            {
                                sensitive_local_variables.add(v);                            
                            }
                        }
                    }System.out.println();
                    StackFrame sf=event.thread().frame(0);
                    for(LocalVariable v:sf.visibleVariables())
                    {
                        if(sf.getValue(v)!=null)
                        {
                            variables_old_value.put(v,sf.getValue(v));
                        }
                        else
                        {
                            variables_old_value.put(v,null);
                        }
                    }
                    variables_new_value=new HashMap<>(variables_old_value);
                    System.out.println("1st breakpoint hit at=== "+event.location().lineNumber());                                     
                    StepRequest st=mgr.createStepRequest(event.thread(),StepRequest.STEP_LINE,StepRequest.STEP_OVER);
                    st.addCountFilter(1);
                    st.addClassFilter("*."+fname);              
                    st.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                    st.enable();  
                    sensitive_source_classes.addAll(sensitive_sink_classes);
                    sensitive_source_classes.addAll(flow_classes);
                    for(String cs:sensitive_source_classes)
                    {
                        MethodEntryRequest menr = mgr.createMethodEntryRequest();
                        menr.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                        menr.addClassFilter(cs);
                        menr.addThreadFilter(event.thread());
                        menr.enable();
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
                line.get(event.thread()).ln=event.location().lineNumber();
                EventRequestManager mgr = vm.eventRequestManager();
               // int ln=event.location().lineNumber();
                if(b2==lineJustExecuted)
                {
                    mgr.deleteEventRequest(mgr.stepRequests().get(0));
                    mgr.deleteEventRequests(mgr.methodEntryRequests());
                    mgr.deleteEventRequests(mgr.breakpointRequests());
                    mgr.deleteEventRequests(mgr.modificationWatchpointRequests());
                    mgr.deleteEventRequests(mgr.accessWatchpointRequests());
                    System.out.println("second breakpoint at "+b2);
                    uptime = System.currentTimeMillis();

                    long days1 = TimeUnit.MILLISECONDS.toDays(uptime);
                    uptime -= TimeUnit.DAYS.toMillis(days);

                    long hours1 = TimeUnit.MILLISECONDS.toHours(uptime);
                    uptime -= TimeUnit.HOURS.toMillis(hours);

                    long minutes1 = TimeUnit.MILLISECONDS.toMinutes(uptime);
                    uptime -= TimeUnit.MINUTES.toMillis(minutes);

                    long seconds1 = TimeUnit.MILLISECONDS.toSeconds(uptime);
                    System.out.println((minutes1-minutes)+" "+(seconds1-seconds));
                }
                else
                {
                // System.out.println(event.thread().frame(0).toString()+" Steeeeeeeeeeeeep eventttttttttttttttttttttttttttttttttttt at== "+event.location().lineNumber());                                  
                   mgr.deleteEventRequest(event.request());
                   //System.err.print("Stepevent  "+event.thread().frame(0).location());
                    if(!modified_class_variable_name.equals(""))
                    {                        

                        // System.err.println(modified_class_variable_name+"  modified to "+modified_class_variable_value.toString());
                         if(last_class_var_access.containsValue(modified_class_variable_value))
                         {
                             for(String class_var_accessed_name:last_class_var_access.keySet())
                             {
                                Value last_class_variable_access_value=last_class_var_access.get(class_var_accessed_name);
                                if(sensitive_class_variables.contains(class_var_accessed_name))
                                {
                                    System.err.println(class_var_accessed_name+"->"+modified_class_variable_name+" "+(line.get(event.thread()).ln-1));
                                    sensitive_class_variables.add(modified_class_variable_name);
                                }
                                taint_information_class.put(modified_class_variable_name, taint_information_class.get(class_var_accessed_name)+" "+taint_information_class.get(modified_class_variable_name)+" "+class_var_accessed_name+":line-"+lineJustExecuted);                               
                             }
                                                                                           
                         }
                         else if(variables_new_value.containsValue(modified_class_variable_value))
                         {

                                for(LocalVariable mm:variables_old_value.keySet())
                                {
                                    Value tpp=variables_new_value.get(mm);
                                    if((tpp!=null)&&(tpp.equals(modified_class_variable_value)))
                                    {
                                        if(sensitive_local_variables.contains(mm))
                                        {
                                           System.err.println(mm.name()+"->"+modified_class_variable_name+" "+(line.get(event.thread()).ln-1));
                                           sensitive_class_variables.add(modified_class_variable_name);
                                        }
                                        taint_information_class.put(modified_class_variable_name, taint_information_local.get(mm)+" "+taint_information_class.get(modified_class_variable_name)+" "+mm.name()+":line-"+lineJustExecuted);
                                    }
                                }
                         }
                         else if(sensitive_class_variables.contains(modified_class_variable_name))
                         {
                             sensitive_class_variables.remove(modified_class_variable_name);
                         }
                         if(!last_Sensitive_Source_Calls.equals(""))
                         {
                             if(Sensitive_Source_Calls_line_no==lineJustExecuted)
                             {
                                 sensitive_class_variables.add(modified_class_variable_name);
                                 taint_information_class.put(modified_class_variable_name, taint_information_class.get(modified_class_variable_name)+" "+last_Sensitive_Source_Calls+":line-"+lineJustExecuted);
                             }
                             last_Sensitive_Source_Calls="";
                         }
                         modified_class_variable_name="";
                         modified_class_variable_value=null;
                    }
                   StackFrame sf=event.thread().frame(0);
                   for(LocalVariable v:sf.visibleVariables())
                   {
                       //System.err.print(v.name()+":"+sf.getValue(v)+" ");
                          // varvl1.put(v,sf.getValue(v).toString());
                       if((sf.getValue(v)!=null)&&(!sf.getValue(v).equals(variables_new_value.get(v))))
                       {   
                           // for class variables accessWatchPoint
                           if(last_class_var_access.containsValue(sf.getValue(v)))
                           {
                                System.err.println("class variable accesssedddddddd");
                                for(String class_var_accessed_name:last_class_var_access.keySet())
                                {
                                    Value last_class_variable_access_value=last_class_var_access.get(class_var_accessed_name);
                                    if(sensitive_class_variables.contains(class_var_accessed_name))
                                    {
                                        System.err.println(class_var_accessed_name+"->"+v.name()+" "+(line.get(event.thread()).ln-1));
                                        sensitive_local_variables.add(v);
                                    }
                                    taint_information_local.put(v, taint_information_local.get(class_var_accessed_name)+" "+taint_information_local.get(v)+" "+class_var_accessed_name+":line-"+lineJustExecuted);                                    
                                }
                           }
                           else if(variables_new_value.containsValue(sf.getValue(v)))
                           {
                               HashSet <LocalVariable>tmp=new HashSet<>();
                               for(LocalVariable mm:variables_old_value.keySet())
                               {
                                   Value tpp=variables_new_value.get(mm);
                                   if((tpp!=null)&&(tpp.equals(sf.getValue(v))))
                                   {
                                       if(sensitive_local_variables.contains(mm))
                                       {
                                          System.err.println(mm.name()+"->"+v.name()+" "+(line.get(event.thread()).ln-1));
                                          tmp.add(v);
                                       }
                                       taint_information_local.put(v, taint_information_local.get(mm)+" "+taint_information_local.get(v)+" "+mm.name()+":line-"+lineJustExecuted);
                                   }
                               }
                               sensitive_local_variables.addAll(tmp);
                           }
                           else if(sensitive_local_variables.contains(v))
                           {
                               sensitive_local_variables.remove(v);
                           }
                           if(!last_Sensitive_Source_Calls.equals(""))
                           {
                               if(Sensitive_Source_Calls_line_no==lineJustExecuted)
                               {
                                   sensitive_local_variables.add(v);
                                   taint_information_local.put(v, taint_information_local.get(v)+" "+last_Sensitive_Source_Calls+":line-"+lineJustExecuted);
                               }
                               last_Sensitive_Source_Calls="";
                           }
                           variables_new_value.put(v,sf.getValue(v));
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
                   st.addClassFilter("*."+fname);
                   st.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                   st.enable(); 
                   variables_old_value=new HashMap<>(variables_new_value);
                }
                                
                System.out.print("At "+lineJustExecuted+" Sensitive var:"+sensitive_local_variables.size()+sensitive_class_variables+"|| ");
                for(LocalVariable sv:sensitive_local_variables)
                {
                    System.out.print(sv.name()+" ");
                }
                for(String classVarName:sensitive_class_variables)
                {
                    System.out.print(classVarName+" ");
                }                
                last_class_var_access.clear();
                System.out.println();
            } catch (Exception ex) 
            {
               //System.err.println("errorrrrrrr at "+event.location()+"  "+ex.toString());
               ex.printStackTrace();
            }
            lineJustExecuted=event.location().lineNumber();
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
            ArrayList <Integer>temp_lines=new ArrayList<>();
            for(Location ln:event.referenceType().allLineLocations())
            {
                temp_lines.add(ln.lineNumber());
              //  System.out.print(ln.lineNumber()+" ");
            }
            temp_lines.sort((i1,i2)->Integer.compare(i1, i2));
            System.out.println(temp_lines);
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
                ArrayList <Location>l1=(ArrayList <Location>) event.referenceType().locationsOfLine(b1);
                if(l1.size()>1)
                {
                    System.err.println("more than one location possible");
                }
                BreakpointRequest b1=mgr.createBreakpointRequest(l1.get(0));               
                b1.setSuspendPolicy(EventRequest.SUSPEND_EVENT_THREAD);
                b1.addThreadFilter(event.thread());
                b1.enable();
                System.out.println("breakpoints set");
                //  event.referenceType().fieldByName(nextBaseIndent);
            } catch (AbsentInformationException ex) {
                Logger.getLogger(EventThread.class.getName()).log(Level.SEVERE, null, ex);
            }/*
            List<Field> fields = event.referenceType().visibleFields();
            for (Field field : fields) {
                ModificationWatchpointRequest req =
                        mgr.createModificationWatchpointRequest(field);
                AccessWatchpointRequest rw =
                        mgr.createAccessWatchpointRequest(field);
                //  req.addClassFilter("debdesk.*");
                req.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                // req.enable();
                rw.addClassFilter("debdesk.*");*/
                // rw.setSuspendPolicy(EventRequest.SUSPEND_NONE);
                //rw.enable();
           // }
        } catch (Exception ex) {
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
