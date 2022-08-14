#pragma once



class PDBHelp
{
	
public:
	PDBHelp(std::string pdbpath);
    ~PDBHelp();

	bool FileDownloader(std::string& PdbName, std::string& url);
	void PEHeaderReader(std::string* PEFileName, std::string* url);

	bool Load(std::string pdbname, uint64_t Base = 0);

	void EnumSymType(std::string SymNmae, std::string TypeName);

	uint32_t GetSymTypeOffset(std::string SymNmae, std::string TypeName, std::string ChildName, bool& hr);

	uint32_t GetSymTypeOffset(std::string SymNmae, std::string TypeName, std::string ChildName);

	uint64_t GetKernelModuleBase(std::string modulename);

	uint64_t GetSymFuncAddr(std::string funcname, bool& hr);

	uint64_t GetSymFuncAddr(std::string funcname);

	uint64_t GetSymFuncOffset(std::string funcname, bool& hr);

	uint64_t GetSymFuncOffset(std::string funcname);

private:
    HANDLE   hProcess;
	//std::vector<uint64_t> PDBBase;

	std::map<std::string, uint64_t> PDBBase;

	std::string m_pdbpath;

};





