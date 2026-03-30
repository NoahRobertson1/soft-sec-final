#ifndef SOFT_SEC_FINAL_PLAYER_H
#define SOFT_SEC_FINAL_PLAYER_H

namespace Player {
    class Player {
    private:
        int _health;
        const char* _name;
    public:
        Player(const char* name, const int health)
            : _health(health), _name(name) {}

        [[nodiscard]] const char* GetName() const;

        [[nodiscard]] int GetHealth() const;
        void SetHealth(int health);

        void AppyHeal();
        void ApplyDamage();
    };

    void Start();
} // Player

#endif //SOFT_SEC_FINAL_PLAYER_H