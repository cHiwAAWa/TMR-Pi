#pragma once
#include <string>

std::string compute_aes(const std::string& plaintext,const unsigned char* master_key,const std::string& task_id);