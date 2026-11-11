# tacview-realtime-inforcer-falcon-bms-4.38.1.1

in falcon bms, there's no option to make acmi files record every frame, this is fine for normal tacview use but for my acmi to blender plugin its very sluggish and has weird glitching effects
this forces bms to write acmi every frame

example usage: py patch_bms_acmi.py apply --exe "C:\Falcon BMS\Bin\x64\Falcon BMS.exe"

change the directory to the directory of ur bms exe
this will break every bms update dueto use of hardcoded offsets rather than sigs but i'll try update it each bms update which isn't very frequent 
