function out=amsco(text,key,direction)
% AMSCO Cipher encoder/decoder
% This algorithm arranges the plain text into a matrix, alternating digraphs
% and single letters. The number of columns is given by the key length.
% Then, the columns are rearranged using the key order and the text is
% read vertically.
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Syntax: 	out=amsco(text,key,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is a character array or a string scalar of digits used as key.
%                 It must represent a valid permutation of 1..N (e.g. '3142').
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
% out=amsco('Hide the gold into the tree stump','3142',1)
%
% out=amsco('DOOEPHIETHIEGNTTRUMETLDTHES','3142',-1)
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text)
    text = char(text);
end
if isstring(key)
    key = char(key);
end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% Validate key: digits only
assert(~isempty(key) && all(key>='0' & key<='9'), ...
    'Key must be a non-empty char vector of digits (e.g. ''3142'').')

% Convert key into a numeric vector
K = double(key) - 48;
LK = numel(K);

% Key must be a permutation of 1..LK
sK = sort(K);
assert(isequal(sK,1:LK), ...
    'This key cannot be used. Digits must form a permutation of 1..%d.',LK)
clear sK

% Index of ordered columns
[~,Idx] = sort(K);
clear K

% ASCII codes of standard English 26 letters alphabet
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];
ctext = char(ctext);

switch direction
    case 1 % encrypt
        out.plain = ctext;
        out.key = key;

        % check if length of text is multiple of 3; if not, pad with '*'
        M = mod(numel(ctext),3);
        if M ~= 0
            ctext = [ctext repmat('*',1,3-M)];
        end
        clear M

        LT_txt = numel(ctext);
        LT1 = LT_txt/3;
        LTA = LT_txt*4/3;

        % Reshape ctext into a Nx3 matrix; add a fourth column of '*'
        A = reshape([reshape(ctext,3,LT1)' repmat('*',LT1,1)]',1,LTA);
        clear LT1 ctext LT_txt

        % Now we work with doubled columns (single/digraph slots)
        LK2 = LK*2;

        % check if length of A is multiple of LK2; if not, pad with '*'
        M = mod(LTA,LK2);
        if M ~= 0
            Z = LK2 - M;
            A = [A repmat('*',1,Z)];
            LTA = LTA + Z;
            clear Z
        end
        clear M

        % reshape A into NxLK2 columns
        B = reshape(A,LK2,LTA/LK2)';
        clear A

        % Reorder columns using the key
        I = 1:2:LK2;
        I = I(Idx);
        C = B(:,reshape([I;I+1],1,LK2));
        clear B I

        % Reshape C into a 2xZ matrix by blocks
        nBlocks = LTA/LK2;
        Z = LTA/2;
        fine = nBlocks:nBlocks:Z;
        inizio = fine - nBlocks + 1;

        D = repmat('*',2,Z); % preallocation
        C = C';

        b = 1;
        for colPair = 1:2:LK2
            D(:,inizio(b):fine(b)) = C(colPair:colPair+1,:);
            b = b + 1;
        end
        clear b colPair C inizio fine nBlocks

        % Back reshape D into a single line
        E = reshape(D,1,LTA);
        clear D LTA

        % Erase '*'
        E(E=='*') = [];

        out.encrypted = E;
        clear E LK2

    case -1 % decrypt
        out.encrypted = ctext;
        out.key = key;

        LK2 = LK*2;

        LT = numel(ctext);
        asterisks = floor(LT/3); % number of * for single letters
        LT = LT + asterisks;
        clear asterisks

        R = ceil(LT/LK2); % rows

        % Is the matrix padded?
        M = floor((R*LK2 - LT)/2);

        % The extrapad is an * inserted instead of a digraph
        extrapad = R*LK2 - LT - M*2;

        if M ~= 0
            padded = LK:-1:LK-M+1; % padded columns (in key-space, 1..LK)
        else
            padded = [];
        end
        clear M LT

        % Safe guard for later comparisons
        if isempty(padded)
            minPadded = 0;
        else
            minPadded = min(padded);
        end

        B = repmat('*',R,LK2); % Matrix preallocation

        % Reorder columns using the key
        I = 1:2:LK2;
        I = I(Idx);

        S = 1;
        F = mod(LK,2);

        for J = 1:LK
            H = ismember(Idx(J),padded);

            switch mod(Idx(J),2)
                case 0 % column starting with single letter
                    B(1,I(J)) = ctext(S);
                    S = S + 1;

                    lr = R - H;

                    for X = 2:lr
                        switch F
                            case 0 % even number of columns: continue with single
                                B(X,I(J)) = ctext(S);
                                S = S + 1;

                            case 1 % odd number of columns: alternate single/digraph
                                switch mod(X,2)
                                    case 0
                                        if X==lr && extrapad~=0 && I(J)==minPadded*2-3
                                            B(X,I(J)) = ctext(S);
                                            S = S + 1;
                                        else
                                            B(X,I(J):I(J)+1) = ctext(S:S+1);
                                            S = S + 2;
                                        end
                                    case 1
                                        B(X,I(J)) = ctext(S);
                                        S = S + 1;
                                end
                        end
                    end

                case 1 % column starting with digraph
                    B(1,I(J):I(J)+1) = ctext(S:S+1);
                    S = S + 2;

                    lr = R - H;

                    for X = 2:lr
                        switch F
                            case 0 % even number of columns: continue with digraph
                                if X==lr && extrapad~=0 && I(J)==minPadded*2-3
                                    B(X,I(J)) = ctext(S);
                                    S = S + 1;
                                else
                                    B(X,I(J):I(J)+1) = ctext(S:S+1);
                                    S = S + 2;
                                end

                            case 1 % odd number of columns: alternate single/digraph
                                switch mod(X,2)
                                    case 0
                                        B(X,I(J)) = ctext(S);
                                        S = S + 1;
                                    case 1
                                        if X==lr && extrapad~=0 && I(J)==minPadded*2-3
                                            B(X,I(J)) = ctext(S);
                                            S = S + 1;
                                        else
                                            B(X,I(J):I(J)+1) = ctext(S:S+1);
                                            S = S + 2;
                                        end
                                end
                        end
                    end
            end
        end

        clear S X H I J padded extrapad F LK lr minPadded

        % Back reshape into a vector
        B = reshape(B',1,[]);
        B(B=='*') = [];

        out.plain = B;

        clear B R LK2
end
