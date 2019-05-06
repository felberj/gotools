package gotools;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoTypesAnalyzer extends AnalyzerBase {
  GoTypesAnalyzer() {
    super("Go Types Analyzer", "Analyzes Types like string and slices",
        AnalyzerType.FUNCTION_ANALYZER);
  }

  @Override
  public boolean added(Program program, AddressSetView addressSetView, TaskMonitor taskMonitor,
      MessageLog messageLog) throws CancelledException {
    StructureDataType s = new StructureDataType("GoString", 0);
    s.add(new QWordDataType(), "len", null);
    s.add(new PointerDataType(new CharDataType()), "str", null);
    program.getDataTypeManager().addDataType(s, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType sl = new StructureDataType("GoSlice", 0);
    sl.add(new QWordDataType(), "len", null);
    sl.add(new QWordDataType(), "cap", null);
    sl.add(new PointerDataType());
    program.getDataTypeManager().addDataType(sl, DataTypeConflictHandler.KEEP_HANDLER);
    return false;
  }
}
