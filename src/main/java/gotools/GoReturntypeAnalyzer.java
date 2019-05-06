/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gotools;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import java.util.Vector;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class GoReturntypeAnalyzer extends AnalyzerBase {
  public GoReturntypeAnalyzer() {
    super("Go Return Type Analyzer", "Tries to recover the return type of go binaries.",
        AnalyzerType.FUNCTION_ANALYZER);
    setPriority(AnalysisPriority.LOW_PRIORITY);
  }

  @Override
  public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    this.detectReturnTypes(p, monitor, log);
    return true;
  }

  private void detectReturnTypes(Program p, TaskMonitor m, MessageLog log) {
    for (Function f : p.getFunctionManager().getFunctionsNoStubs(true)) {
      detectReturnTypes(p, m, log, f);
    }
  }

  private void detectReturnTypes(Program p, TaskMonitor m, MessageLog log, Function f) {
    int maxOffset = 0;
    int maxWrite = 0;
    int minWrite = Integer.MAX_VALUE;
    m.setMessage(String.format("return type analysis of %s", f.getName()));
    if (!f.getName().contains("A0r1")) {
      // return;
    }
    try {
      f.setCallingConvention("go__stdcall");
    } catch (InvalidInputException e) {
      log.appendException(e);
    }
    ReferenceManager refMgr = p.getReferenceManager();
    for (Address fromAddr : refMgr.getReferenceSourceIterator(f.getBody(), true)) {
      for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
        if (!ref.isStackReference()) {
          continue;
        }
        StackReference stackRef = (StackReference) ref;
        if (stackRef.getStackOffset() < 0) {
          continue;
        }
        if (stackRef.getStackOffset() > maxOffset) {
          maxOffset = stackRef.getStackOffset();
        }
        if (ref.getReferenceType() != RefType.WRITE) {
          continue; // no indicator of "return" type
        }
        if (stackRef.getStackOffset() > maxWrite) {
          maxWrite = stackRef.getStackOffset();
        }
        if (stackRef.getStackOffset() < minWrite) {
          minWrite = stackRef.getStackOffset();
        }
      }
    }
    // TODO only works for 64 bit binaries
    int pointerSize = 8;
    long totalArgReturnVals = maxOffset / pointerSize;
    int numberOfRet = 0;
    if (minWrite <= maxWrite) {
      numberOfRet = (maxWrite - minWrite) / pointerSize + 1;
    }
    if (totalArgReturnVals > 10) {
      log.appendMsg(String.format(
          "Skipped function %s because it has %d arguments", f.getName(), totalArgReturnVals));
      return;
    }
    long numberOfArgs = totalArgReturnVals - numberOfRet;
    if (f.getReturnType().getLength() != numberOfRet * pointerSize
        || (numberOfRet != 0 && f.getReturn().getStackOffset() != minWrite)) {
      f.setCustomVariableStorage(true);
      try {
        switch (numberOfRet) {
          case 0:
            f.setReturnType(DataType.VOID, SourceType.ANALYSIS);
            break;
          case 1:
            Undefined8DataType t = new Undefined8DataType();
            // The type is set to imported because otherwise we cannot overwrite it
            f.setReturn(t, new VariableStorage(p, minWrite, t.getLength()), SourceType.IMPORTED);
            break;
          default:
            StructureDataType s =
                new StructureDataType(String.format("ret_%d", f.getSymbol().getID()), 0);
            for (int i = 0; i < numberOfRet; i++) {
              s.add(new Undefined8DataType());
            }
            // The type is set to imported because otherwise we cannot overwrite it
            f.setReturn(s, new VariableStorage(p, minWrite, s.getLength()), SourceType.IMPORTED);
            break;
        }
      } catch (InvalidInputException e) {
        log.appendException(e);
      }
    }
    int paramenterLen = 0;
    for (Parameter param : f.getParameters()) {
      paramenterLen += param.getLength();
    }
    if (paramenterLen != numberOfArgs) {
      // Set the parameters
      Parameter[] params = f.getParameters();
      List<Variable> newParams = new Vector<>();
      for (int i = 0; i < numberOfArgs; i++) {
        if (params != null && params.length > i) {
          newParams.add(params[i]);
        } else {
          VariableStorage v =
              f.getCallingConvention().getArgLocation(i, params, new Undefined8DataType(), p);
          try {
            Variable var =
                new ParameterImpl(null, new Undefined8DataType(), v, p, SourceType.ANALYSIS);
            newParams.add(var); // TODO why so complicated?!
          } catch (InvalidInputException e) {
            log.appendException(e);
            return;
          }
        }
      }
      try {
        f.replaceParameters(newParams, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            false, SourceType.ANALYSIS);
      } catch (DuplicateNameException | InvalidInputException e) {
        log.appendException(e);
        return;
      }
    }
    System.out.printf("Function %s has %d arguments and %d return values. Max offset: %d\n",
        f.getName(), numberOfArgs, numberOfRet, maxOffset);
  }
}
