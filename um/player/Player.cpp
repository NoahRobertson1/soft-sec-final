#include "Player.h"
#include "../util/Util.h"

#include <windows.h>

namespace Player {

    const char* Player::GetName() const {
        return _name;
    }
    int Player::GetHealth() const {
        return _health;
    }
    void Player::SetHealth(const int health) {
        _health = health;
    }
    void Player::AppyHeal() {
        _health+=10;
    }
    void Player::ApplyDamage() {
        _health-=10;
    }

    void Start() {
        Player* player = new Player("Player1", 100);

        bool initialRender = true;

        while (true) {
            bool change=true;

            if (initialRender) {
                Util::render(player->GetName(), player->GetHealth());
                initialRender = false;
            }

            if (GetAsyncKeyState(VK_SPACE) & 1) {
                player->AppyHeal();
            }
            else if (GetAsyncKeyState(VK_SHIFT) & 1) {
                player->ApplyDamage();
            }
            else {
                change=false;
            }

            if (change==true) {
                Util::render(player->GetName(), player->GetHealth());
            }
            Sleep(1);
        }
    }
} // Player