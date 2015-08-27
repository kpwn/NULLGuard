# NULLGuard

This prevents binaries lacking __PAGEZERO from running.

Among other things, it fixes tpwn and renders a _ton_ of bugs unexploitable.

note: some older binaries (10.4?) could also be affected, but I haven't yet encountered a non-malicious binary lacking PAGEZERO.

## How do I use this?

First, git clone the repository.
Then, open the .xcodeproj
Use Xcode to compile the kext (kernel extension)
Simply put the compiled kext in /Library/Extensions


sudo chmod -R 755 /Library/Extensions
sudo chown -R 0:0 /Library/Extensions
sudo nvram boot-args=kext-dev-mode=1

kext-dev-mode=1 doesn't worsen the security of OS X 10.10.5. loading unsigned kexts is doable without it for the bad guys, but having someone sign a kext so I can make a simple installer would be better.

== Public Service Announcement ==
by the way, on twitter, I've suggested to use SUIDGuard instead of NULLGuard, but I've heard there may be a SUIDGuard bypass. haven't seen it myself, but apparently NULLGuard is not vulnerable. so, if you can do the steps above, do them instead of relying just on SUIDGuard. since i am not able to sign this, (I'd be very glad if someone trusted were to send a pull request with a signed build / installer!) it's better to make sure people at least have what is easier to install, since they may just drop the ball completely on self-patching. If you came here to see how to compile & install NULLGuard, then you should probably do so, and possibly get both SUIDGuard and NULLGuard installed. I am not aware of any incompatibility.
