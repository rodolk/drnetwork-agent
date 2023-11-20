%.o:	$(PROJECT_ROOT)connectors/%.cpp
	$(CXX) -c $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDE) -o $@ $<