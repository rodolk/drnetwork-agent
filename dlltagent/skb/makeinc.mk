%.o:	$(PROJECT_ROOT)skb/%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE) -o $@ $<
	
%.o:	$(PROJECT_ROOT)skb/%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) -o $@ $<