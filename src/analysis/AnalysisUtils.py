def fixPathName(path):
	if path[0] == 'd':
		return path.replace('d', '.', 1)
	else:
		return path
