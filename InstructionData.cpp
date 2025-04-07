#include "InstructionData.h"



InstructionList InstructionList::readFromFile(const std::string& filePath, DWORD64 baseAddress) {
	std::ifstream file(filePath, std::ios::binary);
	if (!file) {
		throw std::runtime_error("Failed to open file: " + filePath);
	}

	std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	if (buffer.empty()) {
		throw std::runtime_error("File is empty: " + filePath);
	}

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	InstructionList instructionList;

	ZyanUSize offset = 0;
	const ZyanUSize length = buffer.size();
	ZyanU64 runtime_address = baseAddress;

	while (offset < length) {
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		// 解码指令
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer.data() + offset, length - offset, &instruction, operands))) {
			std::cerr << "Warning: Failed to decode instruction at offset: " << offset << std::endl;
			offset++;
			runtime_address++;
			continue;
		}

		// 构造操作数列表
		std::vector<ZydisDecodedOperand> operandVector;
		for (size_t i = 0; i < instruction.operand_count_visible; ++i) {
			operandVector.push_back(operands[i]);
		}

		// 构造机器码字节序列
		std::vector<BYTE> machineCode(buffer.begin() + offset, buffer.begin() + offset + instruction.length);

		// 创建并存储 InstructionData 对象,将初始指针初始化为自己的地址
		InstructionData instData(instruction, operandVector, machineCode, nullptr);
		instructionList.pushBack(instData);

		// 更新偏移量和地址
		offset += instruction.length;
		runtime_address += instruction.length;
	}

	//setRefInstruction(instructionList);


	return instructionList;
}

void InstructionList::print() {
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZyanU64 runtime_address = 0;
	for (auto& inst : instruction) {
		std::cout << "Address: " << std::hex << std::setw(8) << std::setfill('0') << getByInstruction(inst) << std::endl;
		std::cout << "Machine Code: ";
		for (const auto& byte : inst.machineCode()) {
			std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
		}
		std::cout << "\n";

		char formattedInstruction[256] = {};
		ZyanStatus status = ZydisFormatterFormatInstruction(
			&formatter,
			&inst.info(),
			inst.operand().data(),
			static_cast<ZyanU8>(inst.operand().size()),
			formattedInstruction,
			sizeof(formattedInstruction),
			runtime_address,
			nullptr);

		if (ZYAN_SUCCESS(status)) {
			std::cout << "Instruction: " << formattedInstruction << "\n";
		}
		else {
			std::cout << "Error formatting instruction\n";
		}

		const auto& instruction = inst.info();
		const auto& operands = inst.operand();

		std::cout << "Mnemonic: " << ZydisMnemonicGetString(instruction.mnemonic) << "\n";
		std::cout << "Length: " << static_cast<int>(instruction.length) << " bytes\n";
		for (size_t i = 0; i < operands.size(); ++i) {
			const ZydisDecodedOperand& operand = operands[i];
			std::cout << "Operand " << i << ": ";
			if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				std::cout << "Register " << ZydisRegisterGetString(operand.reg.value) << "\n";
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				std::cout << "Immediate 0x" << std::hex << operand.imm.value.u << "\n";
			}
			else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
				std::cout << "Memory\n";
				std::cout << "  Base: " << ZydisRegisterGetString(operand.mem.base) << "\n";

				ZyanI64 displacement = operand.mem.disp.value;
				ZyanU8 displacementSize = operand.mem.disp.size;

				if (displacementSize > 0 && displacementSize < 64) {
					ZyanI64 mask = (1LL << displacementSize) - 1;
					displacement &= mask;
				}

				std::cout << "  Displacement: 0x" << std::hex << displacement << "\n";
			}

			else {
				std::cout << "Unknown Operand\n";
			}
		}
		std::cout << "-------------------------\n";
	}
}

void InstructionList::writeout(const std::string& filepath)
{
	std::ofstream outFile(filepath, std::ios::binary);
	if (!outFile.is_open()) {
		throw std::runtime_error("Failed to open file for writing: " + filepath);
	}

	for (auto& inst : instruction) {
		const auto& machineCode = inst.machineCode();
		outFile.write(reinterpret_cast<const char*>(machineCode.data()), machineCode.size());
	}

	outFile.close();
}


//std::map<std::vector<BYTE>, std::string>& getMap()
//{
//	std::unordered_map<std::string, std::vector<BYTE>> instructionUsingRef;
//
//	//绝对跳转
//	instructionUsingRef["JMPshort"] = { 0xEB };
//	instructionUsingRef["JMP"] = { 0xe9 };
//
//	// 短跳转
//	instructionUsingRef["JAshort"] = { 0x77 };    // 高于（CF=0 且 ZF=0）
//	instructionUsingRef["JAEshort"] = { 0x73 };  // 高于或等于 (CF=0)
//	instructionUsingRef["JBshort"] = { 0x72 };   // 低于 (CF=1)
//	instructionUsingRef["JBEshort"] = { 0x76 };  // 低于或等于（CF=1 或 ZF=1）
//	instructionUsingRef["JCshort"] = { 0x72 };   // 进位 (CF=1)
//	instructionUsingRef["JCXZ"] = { 0xE3 };      // CX=0
//	instructionUsingRef["JECXZ"] = { 0xE3 };     // ECX=0
//	instructionUsingRef["JEshort"] = { 0x74 };   // 等于 (ZF=1)
//	instructionUsingRef["JGshort"] = { 0x7F };   // 大于（ZF=0 且 SF=OF）
//	instructionUsingRef["JGEshort"] = { 0x7D };  // 大于或等于 (SF=OF)
//	instructionUsingRef["JLshort"] = { 0x7C };   // 小于 (SF<>OF)
//	instructionUsingRef["JLEshort"] = { 0x7E };  // 小于或等于（ZF=1 或 SF<>OF）
//	instructionUsingRef["JNLEshort"] = { 0x7F }; // 不小于或等于（ZF=0 且 SF=OF）
//	instructionUsingRef["JNSshort"] = { 0x79 };  // 正数 (SF=0)
//	instructionUsingRef["JSshort"] = { 0x78 };   // 负数 (SF=1)
//	//instructionUsingRef["JZshort"] = { 0x74 };  // 为零 (ZF=0)
//	instructionUsingRef["JNZshort"] = { 0x75 };  // 不为零 (ZF=0)
//	instructionUsingRef["JOshort"] = { 0x70 };   // 溢出 (OF=1)
//	instructionUsingRef["JNGEshort"] = { 0x7C }; // 不大于或等于 (SF<>OF)
//	instructionUsingRef["JPOshort"] = { 0x7B };  // 奇校验 (PF=0)
//	instructionUsingRef["JPEshort"] = { 0x7A };  // 偶校验 (PF=1)
//
//	// 近跳转
//	instructionUsingRef["JA"] = { 0x0F, 0x87 };  // 高于（CF=0 且 ZF=0）
//	instructionUsingRef["JAE"] = { 0x0F, 0x83 }; // 高于或等于 (CF=0)
//	instructionUsingRef["JB"] = { 0x0F, 0x82 };  // 低于 (CF=1)
//	instructionUsingRef["JBE"] = { 0x0F, 0x86 }; // 低于或等于（CF=1 或 ZF=1）
//	instructionUsingRef["JC"] = { 0x0F, 0x82 };  // 进位 (CF=1)
//	instructionUsingRef["JE"] = { 0x0F, 0x84 };  // 相等 (ZF=1)
//	instructionUsingRef["JZ"] = { 0x0F, 0x84 };  // 为零 (ZF=1)
//	instructionUsingRef["JG"] = { 0x0F, 0x8F };  // 大于（ZF=0 且 SF=OF）
//	instructionUsingRef["JGE"] = { 0x0F, 0x8D }; // 大于或等于 (SF=OF)
//	instructionUsingRef["JL"] = { 0x0F, 0x8C };  // 小于 (SF<>OF)
//	instructionUsingRef["JLE"] = { 0x0F, 0x8E }; // 小于或等于（ZF=1 或 SF<>OF）
//	instructionUsingRef["JNO"] = { 0x0F, 0x81 }; // 不上溢 (OF=0)
//	instructionUsingRef["JO"] = { 0x0F, 0x80 };  // 上溢 (OF=1)
//	instructionUsingRef["JNP"] = { 0x0F, 0x8B }; // 奇校验 (PF=0)
//	instructionUsingRef["JP"] = { 0x0F, 0x8A };  // 偶校验 (PF=1)
//	instructionUsingRef["JNS"] = { 0x0F, 0x89 }; // 正数 (SF=0)
//	instructionUsingRef["JS"] = { 0x0F, 0x88 };  // 负数 (SF=1)
//	instructionUsingRef["JNLE"] = { 0x0F, 0x8F };// 不小于或等于（ZF=0 且 SF=OF）
//
//	//调用
//	instructionUsingRef["CALL"] = { 0xE8 };
//
//	std::map<std::vector<BYTE>, std::string> reverseMap;//使用map，因为unorderedmap没有数组做键
//	for (const auto& pair : instructionUsingRef) {
//		reverseMap[pair.second] = pair.first;
//	}
//	return reverseMap;
//}


void InstructionList::setRefInstruction() {
	std::unordered_map<std::string, std::vector<BYTE>> instructionUsingRef;

	//绝对跳转
	instructionUsingRef["JMPshort"] = { 0xEB };
	instructionUsingRef["JMP"] = { 0xe9 };

	// 短跳转
	instructionUsingRef["JAshort"] = { 0x77 };    // 高于（CF=0 且 ZF=0）
	instructionUsingRef["JAEshort"] = { 0x73 };  // 高于或等于 (CF=0)
	instructionUsingRef["JBshort"] = { 0x72 };   // 低于 (CF=1)
	instructionUsingRef["JBEshort"] = { 0x76 };  // 低于或等于（CF=1 或 ZF=1）
	instructionUsingRef["JCshort"] = { 0x72 };   // 进位 (CF=1)
	instructionUsingRef["JCXZ"] = { 0xE3 };      // CX=0
	instructionUsingRef["JECXZ"] = { 0xE3 };     // ECX=0
	instructionUsingRef["JEshort"] = { 0x74 };   // 等于 (ZF=1)
	instructionUsingRef["JGshort"] = { 0x7F };   // 大于（ZF=0 且 SF=OF）
	instructionUsingRef["JGEshort"] = { 0x7D };  // 大于或等于 (SF=OF)
	instructionUsingRef["JLshort"] = { 0x7C };   // 小于 (SF<>OF)
	instructionUsingRef["JLEshort"] = { 0x7E };  // 小于或等于（ZF=1 或 SF<>OF）
	instructionUsingRef["JNLEshort"] = { 0x7F }; // 不小于或等于（ZF=0 且 SF=OF）
	instructionUsingRef["JNSshort"] = { 0x79 };  // 正数 (SF=0)
	instructionUsingRef["JSshort"] = { 0x78 };   // 负数 (SF=1)
	//instructionUsingRef["JZshort"] = { 0x74 };  // 为零 (ZF=0)
	instructionUsingRef["JNZshort"] = { 0x75 };  // 不为零 (ZF=0)
	instructionUsingRef["JOshort"] = { 0x70 };   // 溢出 (OF=1)
	instructionUsingRef["JNGEshort"] = { 0x7C }; // 不大于或等于 (SF<>OF)
	instructionUsingRef["JPOshort"] = { 0x7B };  // 奇校验 (PF=0)
	instructionUsingRef["JPEshort"] = { 0x7A };  // 偶校验 (PF=1)

	// 近跳转
	instructionUsingRef["JA"] = { 0x0F, 0x87 };  // 高于（CF=0 且 ZF=0）
	instructionUsingRef["JAE"] = { 0x0F, 0x83 }; // 高于或等于 (CF=0)
	instructionUsingRef["JB"] = { 0x0F, 0x82 };  // 低于 (CF=1)
	instructionUsingRef["JBE"] = { 0x0F, 0x86 }; // 低于或等于（CF=1 或 ZF=1）
	instructionUsingRef["JC"] = { 0x0F, 0x82 };  // 进位 (CF=1)
	instructionUsingRef["JE"] = { 0x0F, 0x84 };  // 相等 (ZF=1)
	instructionUsingRef["JZ"] = { 0x0F, 0x84 };  // 为零 (ZF=1)
	instructionUsingRef["JG"] = { 0x0F, 0x8F };  // 大于（ZF=0 且 SF=OF）
	instructionUsingRef["JGE"] = { 0x0F, 0x8D }; // 大于或等于 (SF=OF)
	instructionUsingRef["JL"] = { 0x0F, 0x8C };  // 小于 (SF<>OF)
	instructionUsingRef["JLE"] = { 0x0F, 0x8E }; // 小于或等于（ZF=1 或 SF<>OF）
	instructionUsingRef["JNO"] = { 0x0F, 0x81 }; // 不上溢 (OF=0)
	instructionUsingRef["JO"] = { 0x0F, 0x80 };  // 上溢 (OF=1)
	instructionUsingRef["JNP"] = { 0x0F, 0x8B }; // 奇校验 (PF=0)
	instructionUsingRef["JP"] = { 0x0F, 0x8A };  // 偶校验 (PF=1)
	instructionUsingRef["JNS"] = { 0x0F, 0x89 }; // 正数 (SF=0)
	instructionUsingRef["JS"] = { 0x0F, 0x88 };  // 负数 (SF=1)
	instructionUsingRef["JNLE"] = { 0x0F, 0x8F };// 不小于或等于（ZF=0 且 SF=OF）
	instructionUsingRef["JNZ"] = { 0x0F,0x85 };//ZF=0

	//调用
	instructionUsingRef["CALL"] = { 0xE8 };

	std::map<std::vector<BYTE>, std::string> reverseMap;//使用map，因为unorderedmap没有数组做键
	for (const auto& pair : instructionUsingRef) {
		reverseMap[pair.second] = pair.first;
	}

	//获取这个指令指向的那个指令
	auto findRefAddr = [&](auto& inst, size_t opcodeSize)
		{
			auto opLen = inst.machineCode().size() - opcodeSize;
			if (opLen != 1 && opLen != 4) {
				throw std::invalid_argument("len is not valid");
			}

			size_t targetOffsetFromZeroAddress = getByInstruction(inst) + inst.machineCode().size();
			DWORD offset = 0;
			for (size_t i = opLen + opcodeSize - 1; i >= opcodeSize; --i) {//倒序遍历，因为小端序
				offset <<= 8;
				offset += inst.machineCode()[i];
			}

			if (opcodeSize == 1 && (inst.machineCode()[0] != 0xE9 && inst.machineCode()[0] != 0xE8))
				targetOffsetFromZeroAddress += static_cast<char>(offset);
			else
				targetOffsetFromZeroAddress += static_cast<int>(offset);

			inst.ptrAddr() = &getByAddr(targetOffsetFromZeroAddress);

			//测试输出
			//std::cout << std::hex << getByInstruction(inst) << " using addr: " << getByInstruction(*inst.ptrAddr()) << std::endl;
		};

	for (auto& inst : instruction) {
		if (inst.machineCode()[0] == 0x0f) {
			if (reverseMap.contains({ 0x0f, inst.machineCode()[1] })) {
				findRefAddr(inst, 2);
			}
			continue;
		}

		if (reverseMap.contains({ inst.machineCode()[0] })) {
			findRefAddr(inst, 1);
		}
	}


}


void removeShortFromString(std::string& str) {
	std::string suffix = "short";
	if (str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0) {
		str.erase(str.size() - suffix.size());
	}
}


void InstructionList::resetRefInstruction()
{

	std::unordered_map<std::string, std::vector<BYTE>> instructionUsingRef;

	//绝对跳转
	instructionUsingRef["JMPshort"] = { 0xEB };
	instructionUsingRef["JMP"] = { 0xe9 };

	// 短跳转
	instructionUsingRef["JAshort"] = { 0x77 };    // 高于（CF=0 且 ZF=0）
	instructionUsingRef["JAEshort"] = { 0x73 };  // 高于或等于 (CF=0)
	instructionUsingRef["JBshort"] = { 0x72 };   // 低于 (CF=1)
	instructionUsingRef["JBEshort"] = { 0x76 };  // 低于或等于（CF=1 或 ZF=1）
	instructionUsingRef["JCshort"] = { 0x72 };   // 进位 (CF=1)
	instructionUsingRef["JCXZ"] = { 0xE3 };      // CX=0
	instructionUsingRef["JECXZ"] = { 0xE3 };     // ECX=0
	instructionUsingRef["JEshort"] = { 0x74 };   // 等于 (ZF=1)
	instructionUsingRef["JGshort"] = { 0x7F };   // 大于（ZF=0 且 SF=OF）
	instructionUsingRef["JGEshort"] = { 0x7D };  // 大于或等于 (SF=OF)
	instructionUsingRef["JLshort"] = { 0x7C };   // 小于 (SF<>OF)
	instructionUsingRef["JLEshort"] = { 0x7E };  // 小于或等于（ZF=1 或 SF<>OF）
	instructionUsingRef["JNLEshort"] = { 0x7F }; // 不小于或等于（ZF=0 且 SF=OF）
	instructionUsingRef["JNSshort"] = { 0x79 };  // 正数 (SF=0)
	instructionUsingRef["JSshort"] = { 0x78 };   // 负数 (SF=1)
	//instructionUsingRef["JZshort"] = { 0x74 };  // 为零 (ZF=0)
	instructionUsingRef["JNZshort"] = { 0x75 };  // 不为零 (ZF=0)
	instructionUsingRef["JOshort"] = { 0x70 };   // 溢出 (OF=1)
	instructionUsingRef["JNGEshort"] = { 0x7C }; // 不大于或等于 (SF<>OF)
	instructionUsingRef["JPOshort"] = { 0x7B };  // 奇校验 (PF=0)
	instructionUsingRef["JPEshort"] = { 0x7A };  // 偶校验 (PF=1)

	// 近跳转
	instructionUsingRef["JA"] = { 0x0F, 0x87 };  // 高于（CF=0 且 ZF=0）
	instructionUsingRef["JAE"] = { 0x0F, 0x83 }; // 高于或等于 (CF=0)
	instructionUsingRef["JB"] = { 0x0F, 0x82 };  // 低于 (CF=1)
	instructionUsingRef["JBE"] = { 0x0F, 0x86 }; // 低于或等于（CF=1 或 ZF=1）
	instructionUsingRef["JC"] = { 0x0F, 0x82 };  // 进位 (CF=1)
	instructionUsingRef["JE"] = { 0x0F, 0x84 };  // 相等 (ZF=1)
	instructionUsingRef["JZ"] = { 0x0F, 0x84 };  // 为零 (ZF=1)
	instructionUsingRef["JG"] = { 0x0F, 0x8F };  // 大于（ZF=0 且 SF=OF）
	instructionUsingRef["JGE"] = { 0x0F, 0x8D }; // 大于或等于 (SF=OF)
	instructionUsingRef["JL"] = { 0x0F, 0x8C };  // 小于 (SF<>OF)
	instructionUsingRef["JLE"] = { 0x0F, 0x8E }; // 小于或等于（ZF=1 或 SF<>OF）
	instructionUsingRef["JNO"] = { 0x0F, 0x81 }; // 不上溢 (OF=0)
	instructionUsingRef["JO"] = { 0x0F, 0x80 };  // 上溢 (OF=1)
	instructionUsingRef["JNP"] = { 0x0F, 0x8B }; // 奇校验 (PF=0)
	instructionUsingRef["JP"] = { 0x0F, 0x8A };  // 偶校验 (PF=1)
	instructionUsingRef["JNS"] = { 0x0F, 0x89 }; // 正数 (SF=0)
	instructionUsingRef["JS"] = { 0x0F, 0x88 };  // 负数 (SF=1)
	instructionUsingRef["JNLE"] = { 0x0F, 0x8F };// 不小于或等于（ZF=0 且 SF=OF）
	instructionUsingRef["JNZ"] = { 0x0F,0x85 };//ZF=0

	//调用
	instructionUsingRef["CALL"] = { 0xE8 };

	std::map<std::vector<BYTE>, std::string> reverseMap;//使用map，因为unorderedmap没有数组做键
	for (const auto& pair : instructionUsingRef) {
		reverseMap[pair.second] = pair.first;
	}

	//预处理，先将2长度指令后插入4个nop，如果之后这种指令变成2+4长度，就删除后面的nop，否则不变
	for (auto it = instruction.begin(); it != instruction.end(); ++it)
	{
		if (!it->ptrAddr())continue;
		if (reverseMap.contains({ 0x0f, it->machineCode()[1] }) ||//近跳转
			it->machineCode()[0] == 0xe8 ||//call
			it->machineCode()[0] == 0xe9)continue;
		if (reverseMap.contains({ it->machineCode()[0] }))
		{
			if (it->machineCode()[0] == 0xeb)
			{
				InstructionData nop({ 0x90,0x90,0x90 }, nullptr);
				insertAfter(*it, nop);
				continue;
			}
			InstructionData nop({ 0x90,0x90,0x90,0x90 }, nullptr);
			insertAfter(*it, nop);
		}

	}


	for (auto it = instruction.begin(); it != instruction.end(); ++it)
	{
		if (!it->ptrAddr())continue;

		//std::cout << "-----------------------" << std::endl;
		//std::cout << std::hex << instruction.size() << std::endl;
		//int x = 0;
		//for (auto t = instruction.begin(); t != instruction.end(); ++t)
		//{
		//	std::cout << "addr: " << std::hex << &*t << std::endl;
		//	t->printMachineCode();
		//	x++;
		//}
		//Sleep(1000);
		//std::cout << instruction.size() << std::endl;
		//std::cout << std::hex << x << std::endl;
		//std::cout << "-----------------------" << std::endl;

		//std::cout << "input: ";
		//it->printMachineCode();
		//std::cout << "ptr: ";
		//it->ptrAddr()->printMachineCode();
		//std::cout << "ptr addr:" << std::hex << it->ptrAddr() << std::endl;

		size_t OffsetFromZeroAddressSelf = getByInstruction(*it) + it->machineCode().size();
		size_t OffsetFromZeroAddresstarget = getByInstruction(*(it->ptrAddr()));//不知道为什么会有bug，不理解

		std::cout << OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf << std::endl;
		if (it->machineCode()[0] == 0x0f ||
			it->machineCode()[0] == 0xe8 ||//call
			it->machineCode()[0] == 0xe9) {//jmp]
			if (
				it->machineCode()[0] == 0xe8 ||//call
				it->machineCode()[0] == 0xe9)//jmp
			{
				int delta = OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf;
				BYTE* ptr = reinterpret_cast<BYTE*>(&delta);
				it->machineCode()[1] = ptr[0];
				it->machineCode()[2] = ptr[1];
				it->machineCode()[3] = ptr[2];
				it->machineCode()[4] = ptr[3];
				continue;
			}
			if (reverseMap.contains({ 0x0f, it->machineCode()[1] }))
			{
				int delta = OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf;
				BYTE* ptr = reinterpret_cast<BYTE*>(&delta);
				it->machineCode()[2] = ptr[0];
				it->machineCode()[3] = ptr[1];
				it->machineCode()[4] = ptr[2];
				it->machineCode()[5] = ptr[3];
			}
		}
		else if (reverseMap.contains({ it->machineCode()[0] })) {//单字节为短跳转
			if (static_cast<int>(OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf) < -128 || static_cast<int>(OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf) > 127)//如果中间的跨度改变到大于128字节
			{
				auto s = reverseMap[{ it->machineCode()[0] }];
				removeShortFromString(s);
				int delta = OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf - std::next(it)->machineCode().size();//后面的nop会换成这部分代码所以要保证长度的变化
				BYTE* ptr = reinterpret_cast<BYTE*>(&delta);
				it->machineCode() = instructionUsingRef[s];
				it->machineCode().insert(it->machineCode().end(), { ptr[0], ptr[1], ptr[2], ptr[3] });
				//std::cout << "this code len changed" << std::endl;
				auto nit = std::next(it);
				if (nit->machineCode() == std::vector<BYTE>{0x90, 0x90, 0x90, 0x90})
				{
					instruction.erase(nit);
					//std::cout << "removed nop" << std::endl;
				}
			}
			else
			{
				char delta = OffsetFromZeroAddresstarget - OffsetFromZeroAddressSelf;
				//std::cout << "no changed code:" << OffsetFromZeroAddresstarget << " " << OffsetFromZeroAddressSelf << std::endl;
				//std::cout << delta << std::endl;
				it->machineCode()[1] = delta;
			}
		}
		//std::cout << "output: ";
		//it->printMachineCode();

	}
}



DWORD generateRandomNumber(DWORD max = 0xffffffff) {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<DWORD> dis(0, max);

	return dis(gen);
}





void InstructionList::modifyCode()
{
	hideStackString();
	swapCodeBlock();
}

void InstructionList::hideStackString()
{
	for (auto& inst : instruction)
	{
		DWORD num = 0;
		DWORD imm = 0;

		std::string instructionStr = inst.getCodeStr();

		if (sscanf(instructionStr.c_str(), "mov dword ptr [rbp-0x%X], 0x%X", &num, &imm) == 2)
		{
			//std::cout << "num: " << num << "; imm: 0x" << std::hex << imm << std::endl;
			DWORD randomXorData = generateRandomNumber();
			inst.generateMachineCodeAndWrite("mov dword ptr [rbp-#num], #imm", num, imm ^ randomXorData);
			InstructionData newInst({}, nullptr);
			//newInst.generateMachineCodeAndWrite("xor dword ptr [rbp-#num], #imm", num, randomXorData);
			//insertAfter(inst, newInst);
			newInst.generateMachineCodeAndWrite("push rax;mov eax, #imm", num, randomXorData - 1);
			InstructionData newInst2({ 0xeb,0xff,0xc0 }, nullptr);
			InstructionData newInst3({}, nullptr);
			newInst3.generateMachineCodeAndWrite("xor dword ptr [rbp-#num], eax;pop rax", num, imm);
			insertAfter(inst, { newInst,newInst2,newInst3 });

		}
	}
}


template <typename Container>
size_t getContainerSize(const Container& container) {
	size_t count = 0;
	for (auto it = container.begin(); it != container.end(); ++it) {
		++count;
	}
	return count;
}



void InstructionList::swapCodeBlock()
{
	int u = generateRandomNumber(5) + 1;

	for (int k = 0; k < 1; k++)
	{
		int blocknumber = generateRandomNumber(10) + 2;
		std::vector<std::list<InstructionData>::iterator> pBlockStartList;
		std::vector<InstructionData*> pBlockEndJmpList(blocknumber);
		int listSize = size();
		int dividedpart = listSize / blocknumber;
		auto it = instruction.begin();

		for (int i = 0, pos = 0; i < blocknumber; ++i)
		{
			int stepLen = generateRandomNumber(dividedpart);
			pos += stepLen;
			std::advance(it, pos);
			pBlockStartList.push_back(it);
			auto prev = std::prev(it);
			//插入jmp代码到prev后面，指向后面一个指令

			InstructionData jmpCode({ 0xe9,0x00,0x00,0x00,0x00 }, &*it);
			insertAfter(*prev, jmpCode);
			auto prevNext = std::next(prev);
			InstructionData junkCode({ static_cast<BYTE>(generateRandomNumber(0xff)),static_cast<BYTE>(generateRandomNumber(0xff)) }, nullptr);

			insertAfter(*prevNext, junkCode);
			pBlockEndJmpList[i] = &*prev;
		}


		//int rd = generateRandomNumber(pBlockStartList.size() - 1);
		//rd = rd >= 0 ? rd : 0;
		//auto choosedBlock = pBlockStartList[rd];
		//auto choosedBlockEnd = instruction.begin();
		//if (rd != pBlockStartList.size() - 1)
		//	choosedBlockEnd = pBlockStartList[rd + 1];
		//else
		//	choosedBlockEnd = instruction.end();
		//rd = generateRandomNumber(pBlockStartList.size() - 1);
		//rd = rd >= 0 ? rd : 0;

		//auto dst = pBlockStartList[rd];
		//if (dst != choosedBlock)
		//	instruction.splice(dst, instruction, choosedBlock, choosedBlockEnd);
		//std::cout << getContainerSize(instruction) << std::endl;
		int firstIndex = generateRandomNumber(pBlockStartList.size() - 1);
		int insertIndex = generateRandomNumber(pBlockStartList.size() - 1);
		if (firstIndex == insertIndex)continue;
		auto last = instruction.end();
		if (firstIndex + 1 != pBlockStartList.size())
		{
			last = pBlockStartList[firstIndex + 1];
		}
		instruction.splice(pBlockStartList[insertIndex], instruction, pBlockStartList[firstIndex], last);
		//std::cout << getContainerSize(instruction) << std::endl;
	}

	///
	/// 随机一个块，随机另一个块，将第一个块插入第二个块后面
	///
	///




}


void InstructionData::generateMachineCodeAndWrite(const std::string& templateStr, DWORD num, DWORD imm) {
	// 将num和imm转换为十六进制字符串
	std::ostringstream hexNumStream, hexImmStream;
	hexNumStream << std::hex << num;
	hexImmStream << std::hex << imm;

	std::string instruction = templateStr;
	size_t pos;

	// 替换所有 #num
	while ((pos = instruction.find("#num")) != std::string::npos) {
		instruction.replace(pos, 4, "0x" + hexNumStream.str());
	}

	// 替换所有 #imm
	while ((pos = instruction.find("#imm")) != std::string::npos) {
		instruction.replace(pos, 4, "0x" + hexImmStream.str());
	}


	//std::cout << "生成的指令: " << instruction << std::endl;

	ks_engine* ks;
	ks_err err;
	unsigned char* encoding = nullptr;  // 设置为nullptr，让Keystone动态分配内存
	size_t size;
	DWORD64 count;
	// 初始化Keystone引擎
	err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
	if (err != KS_ERR_OK) {
		throw std::runtime_error("Keystone引擎初始化失败");
	}

	// 使用Keystone生成机器码
	if (ks_asm(ks, instruction.c_str(), 0, &encoding, &size, &count) != KS_ERR_OK) {
		std::string errorMessage = "Keystone汇编错误: " + std::string(ks_strerror(ks_errno(ks)));
		ks_close(ks);
		throw std::runtime_error(errorMessage);
	}

	// 将生成的机器码存入machineCode
	this->machineCode() = std::vector<unsigned char>(encoding, encoding + size);

	//std::cout << "生成的机器码: ";
	//for (size_t i = 0; i < size; i++) {
	//	std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(encoding[i]) << " ";
	//}
	//std::cout << std::endl;

	// 释放Keystone分配的内存
	ks_free(encoding);
	ks_close(ks);
}
