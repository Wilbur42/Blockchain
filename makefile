CC = gcc
C_FLAGS =

LD = gcc
LD_FLAGS = -lstdc++

SRC_DIR = src
INC_DIR = inc
OBJ_DIR = obj
BUILD_DIR = build

rwildcard=$(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

SRC = $(call rwildcard,$(SRC_DIR),*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRC))
DIRS = $(wildcard $(SRC_DIR)/*)

OUTPUT = block.exe

build: $(OBJS) link

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@ echo !==== COMPILING $^
# @ mkdir $(@D)
	$(CC) $(C_FLAGS) -c ./$^ -o ./$@ -I./$(INC_DIR)/

link:
	$(LD) -o $(BUILD_DIR)/$(OUTPUT) $(OBJS) $(LD_FLAGS)

clean:
	del /S /F /Q .\$(OBJ_DIR)\*
	del /S /F /Q .\$(BUILD_DIR)\*

run:
	./$(BUILD_DIR)/$(OUTPUT)

all: clean build run
