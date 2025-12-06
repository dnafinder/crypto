function out=condi(text,key,offset,direction)
%CONDI Cipher encoder/decoder
% The Condi cipher is a keyed polyalphabetic substitution method based on a
% dynamic, self-updating shift. It uses a single mixed alphabet generated
% from a keyword. Encryption starts with a user-defined offset and then
% updates the offset after each character, using the position of the
% current plaintext letter in the keyed alphabet. This makes the shift
% sequence depend on both the key and the message itself.
%
% In brief:
%   1) Build a keyed alphabet (remove duplicates from the key, then append
%      the remaining letters A–Z in order).
%   2) Encrypt the first plaintext letter by shifting it by the starting
%      offset within the keyed alphabet.
%   3) Set the next offset to the position of the current plaintext letter
%      in the keyed alphabet.
%   4) Repeat for all letters.
%
% Decryption follows the same rule in reverse, using the recovered
% plaintext to update the offset step by step.
%
% Syntax:
%   out = condi(text,key,offset,direction)
%
% Input:
%   text      - Character array to encode or decode.
%   key       - Keyword used to generate the keyed alphabet.
%   offset    - Starting shift in the keyed alphabet. Its absolute value
%               indicates the magnitude of the shift (1–25); the sign
%               indicates direction (+ right, - left). Zero is not allowed.
%   direction - 1 to encrypt, -1 to decrypt.
%
% Output:
%   out            - Structure with fields:
%     out.plain    - The plaintext (letters only, uppercase).
%     out.key      - The used key (letters only, uppercase).
%     out.offset   - The starting offset.
%     out.encrypted- The ciphertext.
%
% Examples:
%
% out = condi('Hide the gold into the tree stump','leprachaun',6,1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%        offset: 6
%     encrypted: 'GTYGWENJAQFYWRGGENWYCRVJPYS'
%
% out = condi('GTYGWENJAQFYWRGGENWYCRVJPYS','leprachaun',6,-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'GTYGWENJAQFYWRGGENWYCRVJPYS'
%           key: 'LEPRACHAUN'
%        offset: 6
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also rot
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'offset',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-25,'<=',25}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,offset,direction);
clear p

% Set all letters in uppercase and convert into ASCII Code.
text=double(upper(text));
key=double(upper(key));
% Erase all characters that are not into the range 65 - 90
text(text<65 | text>90)=[];
key(key<65 | key>90)=[];

switch direction
    case 1 %encrypt
        out.plain=char(text);
    case -1 %decrypt
        out.encrypted=char(text);
end
out.key=char(key);
out.offset=offset;

% Build keyed alphabet
ckey=unique(key,'stable');
A=65:1:90;
PS=char([ckey A(~ismember(A,ckey))]);
clear ckey A

L=length(text);
tmp=zeros(1,L);

% Modular index shift within keyed alphabet positions (1..26)
fun=@(x,k,d) mod((x-1)+d*k,26)+1;

for I=1:L
    x=find(PS==text(I),1,'first');
    tmp(I)=PS(fun(x,offset,direction));
    switch direction
        case 1 %encrypt
            offset=x;
        case -1 %decrypt
            offset=find(PS==tmp(I),1,'first');
    end
end
clear I L x offset PS fun

switch direction
    case 1 %encrypt
        out.encrypted=char(tmp);
    case -1 %decrypt
        out.plain=char(tmp);
end
clear tmp
