function out=railfence(text,key,direction,varargin)
% RAIL FENCE Cipher encoder/decoder
% The rail fence cipher (also called a zigzag cipher) is a form of
% transposition cipher. It derives its name from the way in which it is
% encoded. In the rail fence cipher, the plain text is written downwards
% and diagonally on successive "rails" of an imaginary fence, then moving
% up when we reach the bottom rail. When we reach the top rail, the message
% is written downwards again until the whole plaintext is written out. The
% message is then read off in rows.
%
% This implementation transposes all characters in the input text after
% converting to uppercase. No characters are removed.
%
% Syntax: 	out=railfence(text,key,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the number of rails (positive integer)
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text (processed)
%           out.key = the used key
%           out.encrypted = the coded text (processed)
%
% Examples:
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: 3
%     encrypted: 'H  DTHRSPIETEGL NOTETE TMDHOI  EU'
% 
% out=railfence('H  DTHRSPIETEGL NOTETE TMDHOI  EU',3,-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'H  DTHRSPIETEGL NOTETE TMDHOI  EU'
%           key: 3
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addParameter(p,'offset',0,@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','>=',0}));
addParameter(p,'roworder',[],@(x) isnumeric(x) && isvector(x));
parse(p,text,key,direction,varargin{:});
offset = p.Results.offset;
roworder = p.Results.roworder;
clear p

if isstring(text); text = char(text); end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% Normalize case (do not remove any character)
text = upper(text);

% Trivial case
if key == 1
    out.key = key;
    switch direction
        case 1
            out.plain = text;
            out.encrypted = text;
        case -1
            out.encrypted = text;
            out.plain = text;
    end
    return
end

% Default roworder = 1:key
if isempty(roworder)
    roworder = 1:key;
else
    roworder = roworder(:).';
end
validateattributes(roworder,{'numeric'},{'real','finite','nonnan','integer','>=',1,'<=',key})
assert(numel(roworder)==key,'roworder must have length = key (number of rails).')
assert(numel(unique(roworder))==key,'roworder must be a permutation of 1..key.')

L = numel(text);
rowsSeq = railRowsWithOffset(key,L,offset);

switch direction
    case 1 % encrypt
        out.plain = text;
        out.key = key;

        rails = cell(1,key);
        for r = 1:key
            rails{r} = '';
        end

        for i = 1:L
            r = rowsSeq(i);
            rails{r}(end+1) = text(i);
        end

        res = '';
        for k = 1:key
            r = roworder(k);
            res = [res rails{r}]; %#ok<AGROW>
        end

        out.encrypted = res;

    case -1 % decrypt
        out.encrypted = text;
        out.key = key;

        counts = zeros(1,key);
        for i = 1:L
            counts(rowsSeq(i)) = counts(rowsSeq(i)) + 1;
        end

        rails = cell(1,key);
        pos = 1;
        for k = 1:key
            r = roworder(k);
            n = counts(r);
            if n>0
                rails{r} = text(pos:pos+n-1);
            else
                rails{r} = '';
            end
            pos = pos + n;
        end
        assert(pos-1==L,'Internal length mismatch during rail splitting.')

        ptr = ones(1,key);
        pt = repmat(' ',1,L);
        for i = 1:L
            r = rowsSeq(i);
            pt(i) = rails{r}(ptr(r));
            ptr(r) = ptr(r) + 1;
        end

        out.plain = pt;
end

end

function rowsSeq = railRowsWithOffset(R,L,offset)
if R == 1
    rowsSeq = ones(1,L);
    return
end

if R == 2
    phase = [1 2];
else
    phase = [1:R R-1:-1:2];
end

LP = numel(phase);
off = mod(offset,LP);

B = ceil((L+off)/LP);
seq = repmat(phase,1,B);
rowsSeq = seq(off+1:off+L);
end
