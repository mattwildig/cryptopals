A question about [Cryptopals Challenge 45](http://cryptopals.com/sets/6/challenges/45/)
(DSA parameter tampering).

The second part of this challenge talks about using a value of _p+1_ for _g_.
As far as I understand things, using _p+1_ (i.e. 1 _mod p_) for _g_ means that
all generated _y_ will be 1 (since _y = g<sup>x</sup> mod p_) as will all
generated _r_ when signing (since _r = g<sup>k</sup> mod p_). When verifying,
all _v_ values will also be 1 (_v = ((g<sup>u<sub>1</sub></sup>y<sup>u<sub>2</sub></sup>)
mod p) mod q_, and _g_ and _y_ are both 1).

This means that any signature where _r_ = 1 will be valid for any message and
any key (since a signature is valid when _v = r_). I can’t see why the two
formulas given (_r = (y<sup>z</sup> mod p) mod z_ and _s = r / z mod q_) are
needed. They work, since they produce an _r_ value of 1, but seem unnecessary.

Obviously these two formulas come from somewhere, so my understanding must be
incomplete. Where have I gone wrong?

---
##Update

I’ve looked at this again, and I think I now see what is going on. The idea is
not to use the tampered _g_ value in the creation of the key, but if you are
able to get your victim to use that _g_ value when validating a signature then
you can provide a signature that will appear valid.
