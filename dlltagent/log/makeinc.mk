%.o:	$(PROJECT_ROOT)log/%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE) -o $@ $<