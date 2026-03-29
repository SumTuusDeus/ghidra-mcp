"""Pydantic input models for all MCP tools."""

from pydantic import BaseModel, Field
from typing import Optional


# --- Session tools ---

class LoadBinaryInput(BaseModel):
    file_path: str = Field(..., description="Absolute path to the binary file")
    force_reanalysis: bool = Field(False, description="Delete existing project and re-analyze")


class RunAnalysisInput(BaseModel):
    analyzers: Optional[list[str]] = Field(None, description="Specific analyzer names to run (empty = all)")


# --- Function tools ---

class ListFunctionsInput(BaseModel):
    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(100, ge=1, le=1000, description="Max results")
    sort_by: str = Field("address", description="Sort order: 'address' or 'name'")


class SearchFunctionsInput(BaseModel):
    query: str = Field(..., min_length=1, description="Substring to search (case-insensitive)")
    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(100, ge=1, le=1000, description="Max results")


class FunctionRefInput(BaseModel):
    name: Optional[str] = Field(None, description="Function name (exact match)")
    address: Optional[str] = Field(None, description="Function address (hex string)")


class CallGraphInput(BaseModel):
    name: Optional[str] = Field(None, description="Function name")
    address: Optional[str] = Field(None, description="Function address")
    depth: int = Field(1, ge=1, le=3, description="Traversal depth")
    direction: str = Field("both", description="'callers', 'callees', or 'both'")


class XrefsInput(BaseModel):
    address: str = Field(..., description="Target address (hex string)")
    direction: str = Field("to", description="'to' or 'from'")
    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(100, ge=1, le=1000, description="Max results")


# --- Data tools ---

class ListStringsInput(BaseModel):
    filter: Optional[str] = Field(None, description="Substring filter (case-insensitive)")
    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(100, ge=1, le=2000, description="Max results")


class PaginationInput(BaseModel):
    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(100, ge=1, le=1000, description="Max results")


class SearchBytesInput(BaseModel):
    pattern: str = Field(..., description="Hex byte pattern with optional ?? wildcards")
    offset: int = Field(0, ge=0, description="Pagination offset")
    limit: int = Field(20, ge=1, le=100, description="Max results")


# --- Annotation tools ---

class RenameFunctionInput(BaseModel):
    old_name: Optional[str] = Field(None, description="Current function name")
    address: Optional[str] = Field(None, description="Function address")
    new_name: str = Field(..., min_length=1, max_length=255, description="New function name")


class RenameVariableInput(BaseModel):
    function_name: Optional[str] = Field(None, description="Function name")
    function_address: Optional[str] = Field(None, description="Function address")
    old_name: str = Field(..., description="Current variable name")
    new_name: str = Field(..., description="New variable name")


class SetCommentInput(BaseModel):
    address: str = Field(..., description="Address to comment")
    comment: str = Field(..., description="Comment text")
    comment_type: str = Field("decompiler", description="'decompiler' or 'disassembly'")


class SetFunctionPrototypeInput(BaseModel):
    address: str = Field(..., description="Function address")
    prototype: str = Field(..., description="C-style prototype, e.g. 'int main(int argc, char **argv)'")


class SetVariableTypeInput(BaseModel):
    function_address: str = Field(..., description="Function address")
    variable_name: str = Field(..., description="Variable to retype")
    new_type: str = Field(..., description="New type name (e.g., 'int', 'char *')")


class StructFieldInput(BaseModel):
    name: str = Field(..., description="Field name")
    type: str = Field(..., description="Field type (e.g., 'int', 'char[32]', 'void *')")
    comment: Optional[str] = Field(None, description="Field comment")


class DefineStructInput(BaseModel):
    name: str = Field(..., description="Struct name")
    fields: list[StructFieldInput] = Field(..., description="Struct fields")
    category: str = Field("/user-defined", description="DataType category path")
    packed: bool = Field(False, description="Pack the struct (no padding)")
