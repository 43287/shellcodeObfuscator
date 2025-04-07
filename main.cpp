#include <cinttypes>
#include <iostream>
#include <fstream>
#include <vector>
#include <Zydis/Zydis.h>
#include <keystone/keystone.h>

//bool readFileToBuffer(const std::string& filepath, std::vector<unsigned char>& buffer)
//{
//	std::ifstream file(filepath, std::ios::binary | std::ios::ate);
//	if (!file.is_open())
//	{
//		std::cerr << "Failed to open file: " << filepath << std::endl;
//		return false;
//	}
//	std::streamsize fSize = file.tellg();
//	file.seekg(0, std::ios::beg);
//	buffer.resize(fSize);
//	if (!file.read(reinterpret_cast<char*>(buffer.data()), fSize))
//	{
//		std::cerr << "Failed to read file: " << filepath << std::endl;
//		return false;
//	}
//	file.close();
//	return true;
//}
//
//void printInstructionStructure(const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand operands[])
//{
//	std::cout << "Instruction Structure:\n";
//	std::cout << "Mnemonic: " << ZydisMnemonicGetString(instruction.mnemonic) << "\n";
//	std::cout << "Length: " << static_cast<int>(instruction.length) << " bytes\n";
//	std::cout << "Opcode: 0x" << std::hex << static_cast<int>(instruction.opcode) << "\n";
//	std::cout << "Operand Count Visible: " << static_cast<int>(instruction.operand_count_visible) << "\n";
//
//	for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i)
//	{
//		const ZydisDecodedOperand& operand = operands[i];
//		std::cout << "Operand " << static_cast<int>(i) << ": \n";
//		switch (operand.type)
//		{
//		case ZYDIS_OPERAND_TYPE_REGISTER:
//			std::cout << "  Type: Register\n";
//			std::cout << "  Register: " << ZydisRegisterGetString(operand.reg.value) << "\n";
//			break;
//		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
//			std::cout << "  Type: Immediate\n";
//			std::cout << "  Value: 0x" << std::hex << operand.imm.value.u << "\n";
//			break;
//		case ZYDIS_OPERAND_TYPE_MEMORY:
//			std::cout << "  Type: Memory\n";
//			std::cout << "  Base: " << ZydisRegisterGetString(operand.mem.base) << "\n";
//			std::cout << "  Index: " << ZydisRegisterGetString(operand.mem.index) << "\n";
//			std::cout << "  Displacement: 0x" << std::hex << operand.mem.disp.value << "(" << (operand.mem.disp.value >= 0 ? operand.mem.disp.value : -operand.mem.disp.value) << ")" << "\n";
//			break;
//		default:
//			std::cout << "  Type: Unknown\n";
//		}
//	}
//	std::cout << "-----------------------------------\n";
//}
//
//
//int main(int argc, char* argv[])
//{
//	ZydisDecoder decoder;
//	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
//
//	ZydisFormatter formatter;
//	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
//
//	std::string filePath = "shellcode.bin";
//	std::vector<unsigned char> buffer;
//	if (!readFileToBuffer(filePath, buffer))
//	{
//		return 0;
//	}
//
//	ZyanU64 runtime_address = 0;
//	ZyanUSize offset = 0;
//	const ZyanUSize length = buffer.size();
//	ZydisDecodedInstruction instruction;
//	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
//
//	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer.data() + offset, length - offset,
//		&instruction, operands)))
//	{
//		printf("%016" PRIX64 "  ", runtime_address);
//		char tmp[256];
//		ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
//			instruction.operand_count_visible, tmp, sizeof(tmp),
//			runtime_address, ZYAN_NULL);
//		puts(tmp);
//
//		printInstructionStructure(instruction, operands);
//
//		offset += instruction.length;
//		runtime_address += instruction.length;
//	}
//
//	return 0;
//}

#include <iomanip>

#include "InstructionData.h"
#include <string>

int main() {
	try {
		// 设置要读取的文件路径
		const std::string filePath = "shellcode.bin";
		// 设置解码时的起始地址
		DWORD64 baseAddress = 0;

		// 从文件中读取指令列表
		InstructionList instructions = InstructionList::readFromFile(filePath, baseAddress);


		// 打印所有指令信息
		//instructions.print();

		instructions.setRefInstruction();
		instructions.modifyCode();
		instructions.resetRefInstruction();

		instructions.writeout("obshellcode.bin");
	}
	catch (const std::exception& ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}

	return 0;
}
