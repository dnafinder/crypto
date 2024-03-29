function out=a1z26(x)
% A1Z26 Cipher encoder/decoder
% A1Z26 is very simple direct substitution cypher, where each alphabet
% letter is replaced by its number in the alphabet. English, 26 letters,
% alphabet is used and all non-alphabet symbols are not transformed.  
%
% Syntax: 	out=a1z26(x)
%
%     Input:
%           x - It can be a characters array or a numbers array. In first
%           case it will encoded; in the second case it will decoded. 
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.encrypted = the coded text
%
% Examples:
%
% out=a1z26('Hide the gold into the tree stump')
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%     encrypted: [8 9 4 5 20 8 5 7 15 12 4 9 14 20 15 20 8 5 20 18 5 5 19 20 21 13 16]
%
% out=a1z26([8 9 4 5 20 8 5 7 15 12 4 9 14 20 15 20 8 5 20 18 5 5 19 20 21 13 16])
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: [8 9 4 5 20 8 5 7 15 12 4 9 14 20 15 20 8 5 20 18 5 5 19 20 21 13 16]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%

if all(isnumeric(x)) % decrypt
    % check that all numbers are between 1 and 26
    assert(all(ismember(x,1:1:26)),'All numbers must be between 1 and 26') 
    out.encrypted=x;
    % In ASCII Code Uppercase letteres are between 65 and 90; so add 64 and
    % convert numbers into letters. 
    out.plain=char(x+64);
elseif ischar(x) % encrypt
    % Set all letters in uppercase and convert into ASCII Code.
    text=upper(x); ctext=double(text); 
    % Erase all characters that are not into the range 65 - 90
    ctext(ctext<65 | ctext>90)=[];
    out.plain=x;
    % In ASCII Code Uppercase letteres are between 65 and 90; so subtract 64
    out.encrypted=ctext-64;
end