#include <iostream>
#include <windows.h>
#include "player/Player.h"
#include "protection/Protection.h"

int main() {
    int level;
    std::cout << "Set protection level 1, 2, 3 ";
    std::cin >> level;

    if (level == 1) {
        Player::Start();
    }
    else if (level == 2) {
        Protection::Level2::Start();
    }
    else if (level == 3) {
        Protection::Level3::Start();
    }
    else {
        std::cout << "Invalid Level...";
        Sleep(2000);
    }
}