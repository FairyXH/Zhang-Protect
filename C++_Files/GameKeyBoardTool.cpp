#include <Windows.h>
#include <stdio.h>
#include <random>
#include <cstdlib>

constexpr int MIN = 200;
constexpr int MAX = 300;
std::random_device rd;
std::mt19937 eng(rd());
std::uniform_int_distribution<int> distr(MIN, MAX);

BYTE scan_code(DWORD pKey)
{
    const DWORD result = MapVirtualKey(pKey, MAPVK_VK_TO_VSC);
    return static_cast<BYTE>(result);
}

void press_key(DWORD pKey)
{
    keybd_event(static_cast<BYTE>(pKey), scan_code(pKey), 0, 0);
}

void release_key(DWORD pKey)
{
    keybd_event(static_cast<BYTE>(pKey), scan_code(pKey), KEYEVENTF_KEYUP, 0);
}

void press(DWORD pKey)
{
    press_key(pKey);
    Sleep(distr(eng)/10);
    release_key(pKey);
}

void send_keys(bool isWait)
{
    printf("开始执行按键\n");
    //F
    printf("按下键盘F\n");
    press(0x46);
    Sleep(distr(eng));
    //0-9
    printf("按下数字0-9\n");
    for(int i=0x30;i<=0x39;i++){
        press(i);
        Sleep(distr(eng)/10);
    }
    Sleep(distr(eng));
    //W
    printf("按下键盘W\n");
    press_key(0x57);
    Sleep(distr(eng));
    release_key(0x57);
    Sleep(distr(eng));
    //S
    printf("按下键盘S\n");
    press_key(0x53);
    Sleep(distr(eng));
    release_key(0x53);
    Sleep(distr(eng));
    //F11
    printf("按下键盘F11\n");
    for(int i=0;i<2;i++){
    press(0x7A);
    }
    Sleep(distr(eng));
    //BackSpace
    printf("按下键盘BackSpace\n");
    for(int i=0;i<15;i++) {
        press(0x08);
    }
    int next =distr(eng)*10;
    if(isWait){
    printf("单次执行完毕,等待延迟下一次执行: %dms\n",next);
    Sleep(next);
    system("cls");}
}

int main(int argc, char **argv){
    try{
        SetConsoleOutputCP(65001);
        system("title ");
        if(argc > 1){
            int num = atoi(argv[1]);
            for(int i=1;i<=num;i++){
                printf("游戏挂机移动工具：命令行参数要求执行 %d 次\n",num);
                printf("正在执行第 %d 次\n",i);
                if(num > 1){
                send_keys(true);} else {
                    send_keys(false);
                }
            }
            printf("执行完毕,共执行:%d次\n",num);
        } else{
            while (true){
                printf("游戏挂机移动工具：防止游戏检测挂机,可配合其他挂机类软件使用\n当前为无限循环执行模式,可通过命令行参数[int]来指定循环次数\n");
                send_keys(true);
            }
        }
    } catch(...){
        printf("参数错误。");
    }
    return 0;
}
