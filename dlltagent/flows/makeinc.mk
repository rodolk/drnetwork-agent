%.o:	$(PROJECT_ROOT)flows/%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE) -o $@ $<