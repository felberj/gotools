package gotools;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.NotFoundException;

public abstract class AnalyzerBase extends AbstractAnalyzer {
  /**
   * Creates a new defined Data object at the given address.
   *
   * @param address  the address at which to create a new Data object.
   * @param datatype the Data Type that describes the type of Data object to
   *                 create.
   * @return the newly created Data object
   */
  final Data createData(Program p, Address address, DataType datatype) throws Exception {
    Listing listing = p.getListing();
    Data d = listing.getDefinedDataAt(address);
    if (d != null) {
      if (d.getDataType().isEquivalent(datatype)) {
        return d;
      }
      throw new CodeUnitInsertionException("Data conflict at address " + address);
    }
    return listing.createData(address, datatype);
  }

  AnalyzerBase(String name, String description, AnalyzerType type) {
    super(name, description, type);
  }

  MemoryBlock getGopclntab(Program p) throws NotFoundException {
    for (MemoryBlock b : p.getMemory().getBlocks()) {
      if (b.getName().equals(".gopclntab")) {
        return b;
      }
    }
    throw new NotFoundException();
  }

  @Override
  public boolean canAnalyze(Program p) {
    try {
      this.getGopclntab(p);
      return true;
    } catch (NotFoundException e) {
      return false;
    }
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    return true;
  }
}
