%.o:	$(PROJECT_ROOT)http_processing/%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE) -o $@ $<