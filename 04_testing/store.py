from collections import UserDict





class Store:
	cache = dict()

	def __init__(self):
		pass

	def cache_get(self, key):
		return self.cache.get(key)

	def cache_set(self, key, value):
		self.cache[key] = value


	def get(self, key):
		self.storage.get(key)
