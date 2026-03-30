#include "Util.h"
#include <iostream>

namespace Util {
    void render(const char* name, int health) {
        system("cls");
        std::cout << "You are " << name <<
                   "!\n Use [space] to heal and [shift] to deal damage\n Your current health is " << health  << std::endl;
    }
} // Util