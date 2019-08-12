# Angr_Tutorial_For_CTF
angr is a very useful binary analysis framework. Many ctfers like using angr to save their time in CTF.
However angr is a little bit difficult for beginners as its update from version 7 to version 8. And many great tutorials for angr in CTF can't work well. I use this git repo to record my learning experience for angr based on this fantasic tutorial [angr_ctf](https://github.com/jakespringer/angr_ctf), [angr Documentation](https://docs.angr.io/) and [angr API documentation](http://angr.io/api-doc/index.html). Many thanks to them. And I hope that I can keep going for some time and being familiar with angr in the future.

# Installation
I use pypy for running angr in a faster way. Here are my installation instructions.
```bash
conda create -n angr # a clean environment
conda activate angr
conda install -c conda-forge pypy3.5 
wget https://bootstrap.pypa.io/get-pip.py
pypy3 get-pip.py
pypy3 -m pip install angr # then wait and have a rest
```

# How to use this repo
I just use the schedule made by angr_ctf and update the codes support by the newest angr. So if you want to learn angr with me, you can clone this repo and follow the levels. 
- every problem has solution scripts, and you can read the solutions to learn how to use angr. But you need to analysis the binary by yourself.(It's a common problem in CTF in Re or Pwn)
- some codes don't have comment as to the code is clear enough or the same code have been commented in before levels

I think codes' comments are enough, however, if you have questions you can open an issue and we can disscuss. I hope this repo can be helpful.