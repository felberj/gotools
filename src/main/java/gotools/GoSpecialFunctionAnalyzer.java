package gotools;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoSpecialFunctionAnalyzer extends AnalyzerBase {
  public GoSpecialFunctionAnalyzer() {
    super("Golang Special functions analyzer", "analyzes special functiosn in go",
        AnalyzerType.FUNCTION_ANALYZER);
  }

  @Override
  public boolean added(Program program, AddressSetView addressSetView, TaskMonitor taskMonitor,
      MessageLog messageLog) throws CancelledException {
    for (Symbol s : program.getSymbolTable().getSymbols("runtime.panicindex")) {
      Function f = program.getFunctionManager().getFunctionAt(s.getAddress());
      if (f == null) {
        continue;
      }
      f.setNoReturn(true);
    }
    return false;
  }
}
