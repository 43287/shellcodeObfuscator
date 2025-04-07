#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <list>
#include <tuple>
#include <vector>
#include <Windows.h>
#include <Zydis/Zydis.h>
#include <keystone/keystone.h>
#include <string>
#include <optional>
#include <regex>
#include <map>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <random>

//#pragma optimize("", off)
class InstructionData
{
private:
	ZydisDecodedInstruction instruction; // 解码的指令
	std::vector<ZydisDecodedOperand> operands; // 指令操作数
	std::vector<BYTE> machineCodeBytes; // 指令对应的机器码
	InstructionData* referedAddress; // 指令的地址


public:
	InstructionData(const ZydisDecodedInstruction& instruction,
		const std::vector<ZydisDecodedOperand>& operands,
		const std::vector<BYTE>& machineCodeBytes,
		InstructionData* address)
		: instruction(instruction),
		operands(operands),
		machineCodeBytes(machineCodeBytes),
		referedAddress(address) {
	}

	InstructionData(const std::vector<BYTE>& machineCodeBytes,
		InstructionData* address)
		: instruction(ZydisDecodedInstruction{}),
		operands(std::vector<ZydisDecodedOperand>{}),
		machineCodeBytes(machineCodeBytes),
		referedAddress(address) {
	}

	ZydisDecodedInstruction& info() {
		return instruction;
	}

	std::vector<ZydisDecodedOperand>& operand() {
		return operands;
	}

	ZydisDecodedOperand& operand(const size_t index) {
		return operands[index];
	}

	std::vector<BYTE>& machineCode() {
		return machineCodeBytes;
	}

	void printMachineCode()
	{
		for (auto& c : machineCode())
		{
			std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
		}
		std::cout << std::endl;
	}


	InstructionData*& ptrAddr() {
		return referedAddress;
	}

	void generateMachineCodeAndWrite(const std::string& templateStr, DWORD num, DWORD imm);

	std::string getCodeStr() {
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		// 使用 ZydisDecoderDecodeFull 进行解码
		if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, this->machineCode().data(), this->machineCode().size(), &instruction, operands))) {
			char formattedInstruction[256] = {};

			// 格式化解码后的指令
			if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
				&formatter,
				&instruction,
				operands,
				instruction.operand_count_visible,
				formattedInstruction,
				sizeof(formattedInstruction),
				0,
				nullptr))) {
				return std::string(formattedInstruction);
			}
			else {
				return "Error formatting instruction";
			}
		}
		else {
			return "Error decoding instruction";
		}
	}

	template <typename... Args>
	bool formateSame(const std::string& regexPattern, Args&... args) {
		std::regex regex(regexPattern);
		std::smatch matchResults;

		std::string instructionStr = getCodeStr();

		if (std::regex_match(instructionStr, matchResults, regex)) {
			if (matchResults.size() - 1 != sizeof...(args)) {
				throw std::invalid_argument("Number of capturing groups does not match the number of output variables.");
			}

			extractMatchResults(matchResults, args...);
			return true;
		}

		return false; // 匹配失败
	}
};


class InstructionList {
private:
	std::list<InstructionData> instruction;

	//std::list<InstructionData&> refDataList;

public:
	// 通过索引访问指定元素
	InstructionData& at(const size_t index) {
		if (index >= instruction.size()) {
			throw std::out_of_range("Index is out of range");
		}
		auto it = instruction.begin();
		std::advance(it, index); // 使用 std::advance 定位到第 index 个元素
		return *it;
	}

	// 向链表末尾添加元素
	void pushBack(const InstructionData& n) {
		instruction.push_back(n);
	}

	// 获取链表中元素的数量
	size_t size() const {
		return instruction.size();
	}

	//通过地址长度获取instructionData
	InstructionData& getByAddr(const size_t addr) {
		auto it = instruction.begin();
		for (size_t s = 0; s != addr && it != instruction.end(); s += it->machineCode().size(), ++it);
		if (it != instruction.end())
			return *it;
		throw std::out_of_range("getByAddr : address is out of range");
	}



	//通过instructionData获取地址长度
	size_t getByInstruction(InstructionData& i) {
		size_t s = 0;

		for (auto it = instruction.begin(); it != instruction.end(); ++it) {
			if (&(*it) == &i) {
				//std::cout << "found!" << std::endl;
				return s;
			}
			//std::cout << "the addr: " << std::hex << &(*it) << std::endl;
			//std::cout << "the targ: " << std::hex << &i << std::endl;
			//std::cout << std::endl;
			s += it->machineCode().size();
		}

		throw std::out_of_range("getByInstruction : InstructionData not found in the list");
	}



	// 在指定的InstructionData之后插入新的InstructionData
	void insertAfter(const InstructionData& refInst, const InstructionData& newInst) {
		auto it = std::find_if(instruction.begin(), instruction.end(),
			[&refInst](const InstructionData& inst) {
				return &inst == &refInst; // 比较指针地址是否相等
			});

		if (it == instruction.end()) {
			throw std::invalid_argument("Referenced InstructionData not found in the list");
		}

		instruction.insert(std::next(it), newInst);
	}
	// 在指定的InstructionData之后插入一个InstructionData列表
	void insertAfter(const InstructionData& refInst, const std::list<InstructionData>& newInstList) {
		// 查找 refInst 在链表中的位置
		auto it = std::find_if(instruction.begin(), instruction.end(),
			[&refInst](const InstructionData& inst) {
				return &inst == &refInst; // 比较指针地址是否相等
			});

		// 如果未找到 refInst，则抛出异常
		if (it == instruction.end()) {
			throw std::invalid_argument("Referenced InstructionData not found in the list");
		}

		// 使用 std::next 获取 refInst 的下一个位置
		auto insertPos = std::next(it);

		// 将 newInstList 的所有元素插入到 refInst 的后面
		instruction.insert(insertPos, newInstList.begin(), newInstList.end());
	}



	// 读取 shellcode 并解析为 InstructionList
	static InstructionList readFromFile(const std::string& filePath, DWORD64 baseAddress = 0);

	// 打印函数
	void print();

	// 将机器码写入文件
	void writeout(const std::string& filepath);

	//查找指令是否有相对引用，然后将相对引用的指针保存下来
	void setRefInstruction();

	//根据保存的相对引用，重设机器码
	void resetRefInstruction();

	//修改字节码主逻辑
	void modifyCode();

	//隐藏栈上的字符串
	void hideStackString();

	//打乱代码
	void swapCodeBlock();
};

