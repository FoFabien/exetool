#include "exe.hpp"
#include <iomanip>
#include <fstream>
#include <sstream>
#include <iostream>

Exe::Exe()
{
    loaded = false;
}

Exe::~Exe()
{
    //dtor
}

bool Exe::load(const std::string &filename)
{
    std::ifstream fi(filename, std::ios::in | std::ios::binary);
    if(!fi)
        return false;
    loaded = false;
    /*uint16_t buffer;
    fi.read((char*)&buffer, 2);
    if(buffer != 0x5a4D)
        return false;
    header.signature = buffer;
    for(size_t i = 0; i < (sizeof(Header)/2)-1; ++i)
    {
        fi.read((char*)&buffer, 2);
        ((uint16_t*)&header)[1+i] = buffer;
    }
    file = filename;
    loaded = true;*/
    return true;
}

void Exe::printHeader() const
{
    /*if(!loaded)
    {
        std::cout << "No executable loaded" << std::endl;
        return;
    }
    std::cout << "#### " << file << " header ####" << std::endl;
    std::cout << "signature            : 0x" << std::hex << header.signature << std::endl;
    std::cout << "bytes_in_last_block  : 0x" << std::hex << header.bytes_in_last_block << std::endl;
    std::cout << "blocks_in_file       : 0x" << std::hex << header.blocks_in_file << std::endl;
    std::cout << "num_relocs           : 0x" << std::hex << header.num_relocs << std::endl;
    std::cout << "header_paragraphs    : 0x" << std::hex << header.header_paragraphs << std::endl;
    std::cout << "min_extra_paragraphs : 0x" << std::hex << header.min_extra_paragraphs << std::endl;
    std::cout << "max_extra_paragraphs : 0x" << std::hex << header.max_extra_paragraphs << std::endl;
    std::cout << "ss                   : 0x" << std::hex << header.ss << std::endl;
    std::cout << "sp                   : 0x" << std::hex << header.sp << std::endl;
    std::cout << "checksum             : 0x" << std::hex << header.checksum << std::endl;
    std::cout << "ip                   : 0x" << std::hex << header.ip << std::endl;
    std::cout << "cs                   : 0x" << std::hex << header.cs << std::endl;
    std::cout << "reloc_table_offset   : 0x" << std::hex << header.reloc_table_offset << std::endl;
    std::cout << "overlay_number       : 0x" << std::hex << header.overlay_number << std::endl;*/
}

// exe header reading test
bool Exe::test(const std::string &filename)
{
    std::ifstream fi(filename, std::ios::in | std::ios::binary);
    if(!fi)
        return false;
    // variables
    loaded = false;
    uint32_t vint = 0;
    char machine = -1;
    size_t text_id = 96;
    EXE_header EXEHeader;

    std::cout << "##### " << filename << " #####" << std::endl;
    // MZ-DOS Header check
    fi.read((char*)&EXEHeader.MZDOSHeader, sizeof(MZDOS_header));
    if(EXEHeader.MZDOSHeader.e_magic != 0x5a4D)
        return false;
    fi.seekg(60, fi.beg); // PE header address at this position
    fi.read((char*)&vint, sizeof(vint));

    // PE Header check
    std::cout << "PE header addr: 0x" << std::hex << vint << std::dec << std::endl;
    fi.seekg(vint, fi.beg);
    fi.read((char*)&EXEHeader.PEHeader.Signature, sizeof(EXEHeader.PEHeader.Signature));
    if(EXEHeader.PEHeader.Signature != 0x4550)
        return false;
    fi.read((char*)&EXEHeader.PEHeader.FileHeader, sizeof(File_header));

    switch(EXEHeader.PEHeader.FileHeader.Machine) // not sure if it's the best way to check if an exe is 64 bits only
    {
        case 0x014c: machine = 0; break; // 32 bits
        case 0x0200: machine = 1; break; // 64 bits
        case 0x8664: machine = 2; break; // 64 bits
        default: return false;
    }
    std::cout << "Position: 0x" << std::hex << fi.tellg() << std::dec << std::endl; // for debug
    if(machine == 0)
    {
        std::cout << "32 bits" << std::endl;
        fi.read((char*)&EXEHeader.PEHeader.Optional.Header32, sizeof(Optional_header32)-sizeof(Data_directory)*IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        if(EXEHeader.PEHeader.Optional.Header32.Magic != 0x10b)
            return false;
        if(EXEHeader.PEHeader.Optional.Header32.NumberOfRvaAndSizes > 0)
            fi.read((char*)&EXEHeader.PEHeader.Optional.Header32.DataDirectory, sizeof(Data_directory)*EXEHeader.PEHeader.Optional.Header32.NumberOfRvaAndSizes);
    }
    else
    {
        std::cout << "64 bits" << std::endl;
        fi.read((char*)&EXEHeader.PEHeader.Optional.Header64, sizeof(Optional_header64)-sizeof(Data_directory)*IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        if(EXEHeader.PEHeader.Optional.Header64.Magic != 0x20b)
            return false;
        if(EXEHeader.PEHeader.Optional.Header64.NumberOfRvaAndSizes > 0)
            fi.read((char*)&EXEHeader.PEHeader.Optional.Header64.DataDirectory, sizeof(Data_directory)*EXEHeader.PEHeader.Optional.Header64.NumberOfRvaAndSizes);
    }

    // reading the sections
    std::cout << "Numbers of sections: " << EXEHeader.PEHeader.FileHeader.NumberOfSections << std::endl;
    std::cout << "Position: 0x" << std::hex << fi.tellg() << std::dec << std::endl;
    if(EXEHeader.PEHeader.FileHeader.NumberOfSections)
    {
        for(size_t i = 0; i < EXEHeader.PEHeader.FileHeader.NumberOfSections && i < 96; ++i)
        {
            fi.read((char*)&EXEHeader.SectionHeader[i], sizeof(Section_header));
            std::cout << "Section " << i << ": " << EXEHeader.SectionHeader[i].Name << std::endl;
            if(std::string((char*)EXEHeader.SectionHeader[i].Name) == ".text")
                text_id = i;
        }
    }

    /* ---------------------------------
    TODO: code dumping
    --------------------------------- */
    // .text dumping
    if(text_id == 96)
    {
        std::cout << "No .text section" << std::endl;

    }
    else
    {
        fi.seekg(EXEHeader.SectionHeader[text_id].Misc.PhysicalAddress, fi.beg);
        std::ofstream fo(filename + ".txt", std::ios::out | std::ios::trunc | std::ios::binary);
        if(fo)
        {
            vint = 8;
            std::cout << ".text size: " << EXEHeader.SectionHeader[text_id].SizeOfRawData << std::endl;
            for(size_t i = 0; i < EXEHeader.SectionHeader[text_id].SizeOfRawData; ++i)
            {
                std::stringstream ss;
                if(i % 16 == 0)
                {
                    if(i != 0) ss << std::endl;
                    ss << std::setfill('0') << std::setw(8) << std::hex << i << ": ";
                }
                fi.read((char*)&vint, 1);
                ss << std::setfill('0') << std::setw(2) << std::hex << vint << " ";
                if(!ss.str().empty())
                    fo.write(ss.str().c_str(), ss.str().size());
            }
        }
    }
    return true;
}
