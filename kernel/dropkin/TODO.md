
# TODO

- ~~MLS seems to be unpractical. Wipe or refine.~~ File-MLS wiped, but Process MLS kept intact.
- ~~CBAC/CAPSEC seems to be unpractical. Refine.~~
- XATTR-Loading for file security-attributes (CBAC/CAPSEC and previously MLS) is disfunctional.
	- To solve it, there is a LSM-hook called `void *d_instantiate(struct dentry *dentry, struct inode *inode);`
	- This one seems to be called to give the LSM the opportunity to load the XATTRs.

