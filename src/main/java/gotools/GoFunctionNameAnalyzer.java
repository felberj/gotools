package gotools;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class GoFunctionNameAnalyzer extends AnalyzerBase {
    public GoFunctionNameAnalyzer() {
        super("Go Function Name Analyzer", "Recovers function names in go binaries.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
    }

    @Override
    public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        MemoryBlock gopcln;
        try {
            gopcln = getGopclntab(p);
        } catch (NotFoundException e) {
            log.appendException(e);
            throw new CancelledException("gopclntab not found");
        }
        try {
            recoverGoFunctions(p, monitor, log, gopcln);
        } catch (MemoryAccessException e) {
            log.appendException(e);
            return false;
        }
        return true;
    }

    private void recoverGoFunctions(Program p, TaskMonitor m, MessageLog log, MemoryBlock gopc)
            throws MemoryAccessException {
        long pointerSize = 8;
        // TODO this only works for 64bit binaries
        Address a = gopc.getStart().add(8); // skip unimportant header
        long size = p.getMemory().getLong(a);
        a = a.add(pointerSize);
        for (int i = 0; i < size; i++) {
            long funcOffset = p.getMemory().getLong(a); // TODO use createDword
            a = a.add(pointerSize);
            long nameOffset = p.getMemory().getLong(a); // TODO use createDword
            a = a.add(pointerSize);
            Address nameGoStrPointer = gopc.getStart().add(nameOffset + pointerSize);
            Address name = gopc.getStart().add(p.getMemory().getInt(nameGoStrPointer));
            Data d;
            try {
                // TODO we probably know the lenght of the string
                d = createData(p, name, new StringDataType());
            } catch (Exception e) {
                log.appendException(e);
                continue;
            }
            Address funcPointer = p.getAddressFactory().getDefaultAddressSpace().getAddress(funcOffset);
            Function f = p.getFunctionManager().getFunctionAt(funcPointer);
            if (f == null) {
                String functionName = (String)(d.getValue());
                if (functionName.startsWith("type..")) {
                    // TODO what to do with it?
                    p.getListing().setComment(funcPointer, CodeUnit.EOL_COMMENT, functionName);
                    continue;
                }
                if (gopc.contains(funcPointer)) {
                    log.appendMsg(String.format("skipped %s because it is in the section", functionName));
                    continue;
                }
                CreateFunctionCmd cmd = new CreateFunctionCmd(functionName, funcPointer, null, SourceType.ANALYSIS);
                if (!cmd.applyTo(p, m)) {
                    log.appendMsg(String.format("Unable to create function at %s, (expected %s)\n", d.getAddress(), d.getValue()));
                }
                continue;
            }
            try {
                f.setName((String)(d.getValue()), SourceType.ANALYSIS);
            } catch (DuplicateNameException | InvalidInputException e) {
                log.appendException(e);
                continue;
            }
        }
    }
}
