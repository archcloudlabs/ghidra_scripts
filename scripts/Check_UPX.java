
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class Check_UPX extends GhidraScript {
	private String UPX_1 = "UPX";
	private String UPX_2 = "This file is packed with the UPX executable";
	private String UPX_3 = "\\x55\\x50\\x58\\x21\\x50"; // UPX!P
	private String ELF = "\\x7f\\x45\\x4c\\x46"; // ELF magic bytes

	@Override
	protected void run() throws Exception {
		//TODO: Add script code here
		
		println("Triaging " + getCurrentProgram().getName());
		println("Total functions within the current program " + SymbolCount());
		SearchForUPX();
		SearchForELFs();
}


	/**
	 * Search for indicators of UPX within the binary.
	 * @param N/A
	 */
	public void SearchForUPX() {
		Address AddrUpx1 = find(UPX_1); // identify Address of string value or return null
		Address AddrUpx2 = find(UPX_2);
		Address AddrUpx3 = findBytes(getCurrentProgram().getMinAddress(), UPX_3);

		if ((AddrUpx1 != null) || (AddrUpx2 != null) || (AddrUpx3 != null )) {
			println(getCurrentProgram().getName() + " appears to be packed w/ UPX");
			
			if (AddrUpx1 != null) { //
				println("[*] value \"" + UPX_1 + "\" identified at " + AddrUpx1.toString());
			}
			
			if (AddrUpx2 != null) { //
				println("[*] value \"" + UPX_2 + "\" identified at " + AddrUpx2.toString());
			}

			if (AddrUpx3 != null ) { // 
					println("[*] value \"UPX!P\" identified at " + AddrUpx3.toString());
			}

		} else {
			println(getCurrentProgram() + "appears to be NOT be packed w/ UPX");
		}

	}


	/**
	 * Searches for the first 100 occurrences of the ELF header "magic bytes" and prints the location.
	 * @param N/A
	 * @return An array of addresses of type Address where ELF matches
	 */
	public Address[] SearchForELFs() {
		// Match up to 100 embedded ELFs. 100 seems like .....a lot
		Address[] headersMatch = findBytes(getCurrentProgram().getMinAddress(), ELF, 100);

		// skip 1 because we're scanning the ENTIRE address space (or the first 100 embedded bins) and will detect the first one.
		if (headersMatch.length > 1) { 
			for (Address match: headersMatch) {
				println("[*] ELF header identified at: " + match.toString());
			}
		} else {
			println("[!] No embedded ELF header found");
		}
		return headersMatch;
	}
	
	
	/**
	 * This function will count how many symbols exist within the binary.
	 * Lower numbers of symbols *may* indicate a packed binary. or there's just a binary with a couple functions.
	 * @param N/A
	 * @return integer value indicating how many symbols are in the present binary.
	 */
	public int SymbolCount() {
		int count = 0;
		SymbolTable currentSymbolTable = getCurrentProgram().getSymbolTable();
		for (Symbol sym : currentSymbolTable.getAllSymbols(false) ) {
			count += 1;
		}
		return count;
	}

}
