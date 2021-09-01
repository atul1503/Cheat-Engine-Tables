{$lua}

[ENABLE]

local initaccel=1-1e-3
local jerk=1.01
local speedXString='X SPEED'
local speedYString='Y SPEED'

local accel=initaccel


--[[
Instructions:
-------------
This Script adjusts the acceleration of the vehicle by multiplying/dividing it by jerk.
initaccel: Initial acceleration
accel: current acceleration at any point of time.
jerk: Also called the derivative of acceleration in physics.
]]--


t=getAddressList()
x=t.getMemoryRecordByDescription(speedXString)
y=t.getMemoryRecordByDescription(speedYString)


function adjustSpeed()
	x.Value=x.Value*accel
	y.Value=y.Value*accel
end

function gearUp()
accel=accel*jerk
end

function gearDown()
accel=accel/jerk
end


hk1=createHotkey(adjustSpeed(),0x26)

hk2=createHotkey(gearUp(),0x57)

hk3=createHotkey(gearDown(),0x53)

hk4=createHotkey(function()
accel=initmul
end,0x52)





[DISABLE]
hk1.destroy()
hk2.destroy()
hk3.destroy()
hk4.destroy()

