package snesloader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import snesloader.RomReader.RomChunk;

public class ExHiRomLoader implements RomInfoProvider {
	public static final long SNES_HEADER_OFFSET = 0x40_FFC0;
	public static final long MAX_ROM_SIZE = 0x80_0000; //8 MiB
	public static final int ROM_CHUNK_SIZE = 0x8000; //32 KiB

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Program prog, TaskMonitor monitor, RomInfo romInfo)  throws IOException {
		//throw new UnsupportedOperationException("Loading a Ex_HI_ROM format is not implemented yet.");
		
		AddressSpace busSpace = prog.getAddressFactory().getDefaultAddressSpace();

		RomReader reader = new RomReader(romInfo, provider);
		
		for (RomChunk romChunk : reader) {
			//get both the primary and mirrored (if applicable) address for each 32KiB chunk
			List<Address> busAddresses = getBusAddressesForRomChunk(romChunk, busSpace);

			Address primaryAddress = busAddresses.remove(0);
			String primaryBlockName = getRomChunkPrimaryName(romChunk, primaryAddress);
			
			try {
				MemoryBlockUtils.createInitializedBlock(prog, false, primaryBlockName, primaryAddress,
						romChunk.getInputStream(), romChunk.getLength(), "", provider.getAbsolutePath(), true, false,
						true, log, monitor);
			}
			catch (AddressOverflowException e) {
				throw new IllegalStateException("Invalid address range specified: start:" + primaryAddress + ", length:"
						+ romChunk.getLength() + " - end address exceeds address space boundary!");
			}

			int mirrorNum = 1;
			for (Address mirrorAddress : busAddresses) {
				String mirrorBlockName = getRomChunkMirrorName(romChunk, mirrorNum, mirrorAddress);
				MemoryBlockUtils.createByteMappedBlock(prog, mirrorBlockName, mirrorAddress, primaryAddress,
						(int) romChunk.getLength(), String.format("mirror of %s", primaryBlockName), "", true, false,
						true, false, log);
				mirrorNum++;
			}
		}

		return true;
	}

	private static List<Address> getBusAddressesForRomChunk(RomChunk chunk, AddressSpace space) {
		var busAddresses = new ArrayList<Address>();
		long chunkStartAddress = chunk.getRomAddresses().left;

		// Primary mapping.
		// Map the lower 4 MiB to C0-ff:0000-ffff
		if(chunkStartAddress < 0x40_0000)
			busAddresses.add(space.getAddress(chunkStartAddress + 0xC0_0000));
		else if(chunkStartAddress < 0x7E_0000)
			//map to 40-7e:0000-ffff
			busAddresses.add(space.getAddress(chunkStartAddress));
		else if(chunkStartAddress < 0x80_0000)
		{
			// I'll be honest. I have no idea if a ROM dumper would
			// grab chunks like 0x3E0000 from ROM or skip them, since that's RAM.
			// I assume that the dumper retrieves them, but they're either garbage or null.
			// We don't have an official example of a >6MiB cart, so I take a guess.
			if((chunkStartAddress & 0x008000) != 0)
				//map to 3e-3f:8000-ffff
				busAddresses.add(space.getAddress(chunkStartAddress - 0x40_0000));
		}

		// Gap in banks 7e and 7f for RAM.

		// Mirroring
		if((chunkStartAddress & 0x8000) != 0) {
			//mirror chunk to 80-bf:8000-ffff
			if(chunkStartAddress < 0x40_0000)
				busAddresses.add(space.getAddress(chunkStartAddress + 0x80_0000));
			//mirror chunk to 00-3d:8000-ffff
			else if(chunkStartAddress < 0x7E_0000)
				busAddresses.add(space.getAddress(chunkStartAddress - 0x40_0000));
		}
		return busAddresses;
	}

	private static String getRomChunkPrimaryName(RomChunk chunk, Address address) {
		long leftAddr = chunk.getRomAddresses().left;
		int leftBank = (int) ((leftAddr & 0xff_0000) >> 16);
		int leftSmall = (int) (leftAddr & 0xffff);

		long rightAddr = chunk.getRomAddresses().right;
		int rightBank = (int) ((rightAddr & 0xff_0000) >> 16);
		int rightSmall = (int) (rightAddr & 0xffff);

		//format: "rom_BB:AAAA-BB:AAAA"
		//return String.format("rom_%02x:%04x-%02x:%04x", leftBank, leftSmall, rightBank, rightSmall);
		String mappedStartAddress = address.toString();
		String mappedEndAddress = address.add(ROM_CHUNK_SIZE - 1).toString();
		return String.format("%s-%s (rom_%02x:%04x-%02x:%04x)", mappedStartAddress, mappedEndAddress, leftBank, leftSmall, rightBank, rightSmall);
	}

	private static String getRomChunkMirrorName(RomChunk chunk, int mirrorNum, Address address) {
		//format: "rom_BB:AAAA-BB:AAAA_mirror1"
		return String.format("%s_mirror%d", getRomChunkPrimaryName(chunk, address), mirrorNum);
	}

	@Override
	public long getSnesHeaderOffset() {
		return SNES_HEADER_OFFSET;
	}

	@Override
	public long getMaxRomSize() {
		return MAX_ROM_SIZE;
	}

	@Override
	public long getChunkSize() {
		return ROM_CHUNK_SIZE;
	}

	@Override
	public RomLoader getLoaderFunction() {
		return ExHiRomLoader::load;
	}
}
