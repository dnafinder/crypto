function out=railfence(text,key,direction)
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
% out=railfence('Hide the gold into the tree stump',3,1)
%
% out=railfence('H  DTHRSPIETEGL NOTETE TMDHOI  EU',3,-1)
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
parse(p,text,key,direction);
clear p

if isstring(text)
    text = char(text);
end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

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

% Construct repeated motif (phase) for the rails:
% key=3  -> 1 2 3 2
% key=4  -> 1 2 3 4 3 2
if key == 2
    phase = [1 2];
else
    phase = [1:key, key-1:-1:2];
end

L  = numel(text);
LP = numel(phase);
B  = ceil(L/LP);

rows = repmat(phase,1,B);
rows = rows(1:L);
cols = 1:L;

% Preallocate a key x L matrix
matrix = NaN(key,L);

% Transform subscripts to index (one char per column)
Ind = sub2ind([key,L],rows,cols);

switch direction
    case 1 % encrypt
        out.plain = text;
        out.key = key;

        % Fill the matrix with the ASCII codes of the text
        matrix(Ind) = double(text);

        % Read off rows (transpose then linearize)
        tmp = matrix';
        tmp = tmp(:)';
        tmp(isnan(tmp)) = [];

        out.encrypted = char(tmp);

    case -1 % decrypt
        out.encrypted = text;
        out.key = key;

        % Build rail map
        matrix(Ind) = rows;

        % Convert text into ASCII codes
        ctext = double(text);

        % Fill rails in order from top to bottom
        for r = 1:key
            idx = (matrix == r);
            s = nnz(idx);
            if s > 0
                matrix(idx) = ctext(1:s);
                ctext(1:s) = [];
            end
        end

        % Read zigzag order by columns (one char per column)
        tmp = matrix(:);
        tmp(isnan(tmp)) = [];

        out.plain = char(tmp');
end

end
