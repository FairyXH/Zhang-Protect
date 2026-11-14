#include <Windows.h>
#include <stdio.h>
void down(int vk)
{
    keybd_event(vk,0,0,0);
}
void up(int vk)
{
    keybd_event(vk,0,KEYEVENTF_KEYUP,0);
}
void press(int vk)
{
    down(vk);
    up(vk);
}
int main(){
    try{
    while(true){
        //num lock
        while(!GetKeyState(144)){
            press(144);
        }
        //caps lock
        while(GetKeyState(20)){
            press(20);
        }
        //insert
        //while(!GetKeyState(45)){
        //    press(45);
        // }
        Sleep(10);
    }
    } catch(...){
        if(true){} //占位,遇到错误直接继续执行
    }
}